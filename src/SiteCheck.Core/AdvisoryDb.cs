using System.Reflection;
using System.Text.Json;
using System.Text.Json.Serialization;
using System.Text.RegularExpressions;

namespace SiteCheck.Core;

/// <summary>
/// Local advisory catalogue shipped inside the executable. Built from Retire.js
/// (Apache-2.0) and GitHub Advisory ranges for Next.js. Runtime matching never
/// contacts NVD, GitHub, or Retire.js.
/// </summary>
public static class AdvisoryDb
{
    public const int MaxHits = 40;

    private static readonly JsonSerializerOptions JsonOpts = new()
    {
        PropertyNameCaseInsensitive = true
    };

    private static readonly Lazy<FileDto> File = new(Load);
    private static readonly Lazy<IReadOnlyList<CompiledProduct>> Compiled = new(Compile);

    public static bool CatalogueLoaded
    {
        get
        {
            try
            {
                return File.Value.Products.Count >= 0;
            }
            catch (Exception)
            {
                return false;
            }
        }
    }

    public static string Built => CatalogueLoaded ? File.Value.Built ?? "" : "";
    public static int ProductCount => CatalogueLoaded ? File.Value.Products.Count : 0;
    public static int AdvisoryCount => CatalogueLoaded ? File.Value.Products.Sum(p => p.Vulns?.Count ?? 0) : 0;

    public static IReadOnlyList<StackHint> DetectFromHtml(string html)
    {
        if (string.IsNullOrEmpty(html)) return Array.Empty<StackHint>();
        var hints = new List<StackHint>();
        foreach (var product in Compiled.Value)
        {
            string? version = null;
            string? evidence = null;
            foreach (var rx in product.Extractors)
            {
                Match m;
                try
                {
                    m = rx.Match(html);
                }
                catch (RegexMatchTimeoutException)
                {
                    continue;
                }
                if (!m.Success || m.Groups.Count < 2) continue;
                var v = m.Groups[1].Value;
                if (string.IsNullOrWhiteSpace(v)) continue;
                version = v;
                evidence = "A script or file URL on the homepage named this version.";
                break;
            }
            if (version != null)
            {
                hints.Add(new StackHint(product.Name, version, evidence!));
            }
        }
        return hints;
    }

    public static IReadOnlyList<(CveCatalog.Entry Entry, StackHint Hint)> Match(IEnumerable<StackHint> stack)
    {
        try
        {
            return MatchCore(stack);
        }
        catch (Exception)
        {
            return Array.Empty<(CveCatalog.Entry, StackHint)>();
        }
    }

    private static IReadOnlyList<(CveCatalog.Entry Entry, StackHint Hint)> MatchCore(IEnumerable<StackHint> stack)
    {
        var hits = new List<(CveCatalog.Entry, StackHint)>();
        var seen = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        foreach (var hint in stack)
        {
            if (string.IsNullOrWhiteSpace(hint.Version)) continue;
            foreach (var product in Compiled.Value)
            {
                if (!product.Is(hint.Product)) continue;
                foreach (var vuln in product.Vulns)
                {
                    if (!RangeHit(hint.Version, vuln)) continue;
                    var key = vuln.Id + "|" + product.Name + "|" + hint.Version;
                    if (!seen.Add(key)) continue;
                    hits.Add((
                        new CveCatalog.Entry(
                            product.Name,
                            vuln.Id,
                            vuln.Summary,
                            vuln.Source,
                            _ => true),
                        hint));
                    if (hits.Count >= MaxHits) return hits;
                }
            }
        }
        return hits;
    }

    private static bool RangeHit(string version, VulnDto vuln)
    {
        if (vuln.Ranges is null || vuln.Ranges.Count == 0) return false;
        foreach (var range in vuln.Ranges)
        {
            if (range.Constraints is { Count: > 0 })
            {
                var ok = true;
                foreach (var c in range.Constraints)
                {
                    if (string.IsNullOrEmpty(c.Op) || string.IsNullOrEmpty(c.Version) ||
                        !VersionCmp.Satisfies(version, c.Op, c.Version))
                    {
                        ok = false;
                        break;
                    }
                }
                if (ok) return true;
            }
            else if (VersionCmp.InRetireRange(version, range.AtOrAbove, range.Below))
            {
                return true;
            }
        }
        return false;
    }

    private static FileDto Load()
    {
        var assembly = typeof(AdvisoryDb).Assembly;
        using var stream = assembly.GetManifestResourceStream("advisories.json")
            ?? throw new InvalidOperationException("advisories.json is missing from the assembly.");
        var dto = JsonSerializer.Deserialize<FileDto>(stream, JsonOpts)
            ?? throw new InvalidOperationException("advisories.json could not be read.");
        dto.Products ??= new List<ProductDto>();
        return dto;
    }

    private static IReadOnlyList<CompiledProduct> Compile()
    {
        var list = new List<CompiledProduct>();
        foreach (var p in File.Value.Products)
        {
            if (string.IsNullOrWhiteSpace(p.Name)) continue;
            var extractors = new List<Regex>();
            foreach (var raw in p.Extractors ?? new List<string>())
            {
                var rx = TryCompile(raw);
                if (rx != null) extractors.Add(rx);
            }
            var aliases = new HashSet<string>(StringComparer.OrdinalIgnoreCase) { p.Name };
            foreach (var a in p.Aliases ?? new List<string>())
            {
                if (!string.IsNullOrWhiteSpace(a)) aliases.Add(a);
            }
            list.Add(new CompiledProduct(p.Name, aliases, extractors, p.Vulns ?? new List<VulnDto>()));
        }
        return list;
    }

    private static Regex? TryCompile(string pattern)
    {
        var source = pattern.Replace("§§version§§", @"([0-9]+(?:\.[0-9]+)*)", StringComparison.Ordinal);
        try
        {
            return new Regex(
                source,
                RegexOptions.IgnoreCase | RegexOptions.CultureInvariant | RegexOptions.Compiled | RegexOptions.NonBacktracking,
                TimeSpan.FromMilliseconds(50));
        }
        catch (ArgumentException)
        {
            try
            {
                return new Regex(
                    source,
                    RegexOptions.IgnoreCase | RegexOptions.CultureInvariant | RegexOptions.Compiled,
                    TimeSpan.FromMilliseconds(50));
            }
            catch (ArgumentException)
            {
                return null;
            }
        }
    }

    private sealed record CompiledProduct(
        string Name,
        HashSet<string> Aliases,
        List<Regex> Extractors,
        List<VulnDto> Vulns)
    {
        public bool Is(string product) => Aliases.Contains(product);
    }

    private sealed class FileDto
    {
        public string? Built { get; set; }
        public List<ProductDto> Products { get; set; } = new();
    }

    private sealed class ProductDto
    {
        public string Name { get; set; } = "";
        public List<string>? Aliases { get; set; }
        public List<string>? Extractors { get; set; }
        public List<VulnDto>? Vulns { get; set; }
    }

    private sealed class VulnDto
    {
        public string Id { get; set; } = "";
        public string Summary { get; set; } = "";
        public string Source { get; set; } = "";
        public List<RangeDto>? Ranges { get; set; }
    }

    private sealed class RangeDto
    {
        public string? AtOrAbove { get; set; }
        public string? Below { get; set; }
        public List<ConstraintDto>? Constraints { get; set; }
    }

    private sealed class ConstraintDto
    {
        [JsonPropertyName("op")]
        public string? Op { get; set; }
        public string? Version { get; set; }
    }
}
