using Avalonia;
using Avalonia.Controls;

namespace SiteCheck.Desktop;

/// <summary>
/// Same fill-width, last-row-stretch layout as the Windows WPF panel.
/// </summary>
public sealed class ResponsiveCardPanel : Panel
{
    public static readonly StyledProperty<double> MinColumnWidthProperty =
        AvaloniaProperty.Register<ResponsiveCardPanel, double>(nameof(MinColumnWidth), 560);

    public static readonly StyledProperty<int> MaxColumnsProperty =
        AvaloniaProperty.Register<ResponsiveCardPanel, int>(nameof(MaxColumns), 3);

    static ResponsiveCardPanel()
    {
        AffectsMeasure<ResponsiveCardPanel>(MinColumnWidthProperty, MaxColumnsProperty);
    }

    public double MinColumnWidth
    {
        get => GetValue(MinColumnWidthProperty);
        set => SetValue(MinColumnWidthProperty, value);
    }

    public int MaxColumns
    {
        get => GetValue(MaxColumnsProperty);
        set => SetValue(MaxColumnsProperty, value);
    }

    private int ColumnCount(double width, int childCount)
    {
        if (childCount <= 1) return 1;
        if (double.IsNaN(width) || double.IsInfinity(width) || width <= 0) return 1;
        var byWidth = Math.Max(1, (int)Math.Floor(width / Math.Max(160, MinColumnWidth)));
        return Math.Max(1, Math.Min(MaxColumns, Math.Min(childCount, byWidth)));
    }

    protected override Size MeasureOverride(Size availableSize)
    {
        var n = Children.Count;
        if (n == 0) return new Size(0, 0);
        var width = double.IsInfinity(availableSize.Width) ? MinColumnWidth : availableSize.Width;
        var cols = ColumnCount(width, n);
        var rows = (int)Math.Ceiling(n / (double)cols);
        var lastCount = n % cols == 0 ? cols : n % cols;
        var height = 0.0;
        var index = 0;
        for (var row = 0; row < rows; row++)
        {
            var count = row == rows - 1 ? lastCount : cols;
            var cellW = Math.Max(1, width / count);
            var rowH = 0.0;
            for (var i = 0; i < count; i++)
            {
                Children[index++].Measure(new Size(cellW, double.PositiveInfinity));
                rowH = Math.Max(rowH, Children[index - 1].DesiredSize.Height);
            }
            height += rowH;
        }

        return new Size(width, height);
    }

    protected override Size ArrangeOverride(Size finalSize)
    {
        var n = Children.Count;
        if (n == 0) return finalSize;
        var cols = ColumnCount(finalSize.Width, n);
        var rows = (int)Math.Ceiling(n / (double)cols);
        var lastCount = n % cols == 0 ? cols : n % cols;
        var y = 0.0;
        var index = 0;
        for (var row = 0; row < rows; row++)
        {
            var count = row == rows - 1 ? lastCount : cols;
            var cellW = finalSize.Width / count;
            var rowStart = index;
            var rowH = 0.0;
            for (var i = 0; i < count; i++)
                rowH = Math.Max(rowH, Children[rowStart + i].DesiredSize.Height);
            for (var i = 0; i < count; i++)
            {
                Children[index++].Arrange(new Rect(i * cellW, y, cellW, rowH));
            }
            y += rowH;
        }

        return new Size(finalSize.Width, y);
    }
}
