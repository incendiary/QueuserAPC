using QueueUserAPC;
using Xunit;

namespace QueuserAPC.Tests;

public class ProgramTests
{
    [Fact]
    public void ParseUrl_NoArgs_ThrowsArgumentException()
    {
        var ex = Assert.Throws<ArgumentException>(() => Program.ParseUrl([]));
        Assert.Contains("required", ex.Message, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public void ParseUrl_ValidHttpUrl_ReturnsUrl()
    {
        const string url = "http://192.168.1.10/payload.bin";
        Assert.Equal(url, Program.ParseUrl([url]));
    }

    [Fact]
    public void ParseUrl_ValidHttpsUrl_ReturnsUrl()
    {
        const string url = "https://192.168.1.10/payload.bin";
        Assert.Equal(url, Program.ParseUrl([url]));
    }

    [Theory]
    [InlineData("ftp://192.168.1.10/payload.bin")]
    [InlineData("/local/path/payload.bin")]
    [InlineData("not-a-url")]
    public void ParseUrl_InvalidScheme_ThrowsArgumentException(string url)
    {
        var ex = Assert.Throws<ArgumentException>(() => Program.ParseUrl([url]));
        Assert.Contains("http or https", ex.Message, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public void ParseUrl_UrlWithNtFlag_ReturnsUrl()
    {
        const string url = "http://192.168.1.10/payload.bin";
        Assert.Equal(url, Program.ParseUrl(["--nt", url]));
    }

    [Fact]
    public void ParseUrl_NtFlagOnly_ThrowsArgumentException()
    {
        Assert.Throws<ArgumentException>(() => Program.ParseUrl(["--nt"]));
    }

    [Fact]
    public void ParseUseNt_NoFlag_ReturnsFalse()
    {
        Assert.False(Program.ParseUseNt(["http://192.168.1.10/payload.bin"]));
    }

    [Fact]
    public void ParseUseNt_WithFlag_ReturnsTrue()
    {
        Assert.True(Program.ParseUseNt(["--nt", "http://192.168.1.10/payload.bin"]));
    }

    [Fact]
    public void ParseUseNt_FlagCaseInsensitive_ReturnsTrue()
    {
        Assert.True(Program.ParseUseNt(["--NT", "http://192.168.1.10/payload.bin"]));
    }
}
