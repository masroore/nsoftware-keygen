namespace nsoftwareKeygen;

public static class ProductCodes
{
    private static Dictionary<ProductType, string> PRODUCT_PREFIX_MAP = new()
    {
        { ProductType.IPWorks, "IP" },
        { ProductType.SecureBlackbox, "SB" },
        { ProductType.CloudStorage, "ES" },
        { ProductType.CloudMail, "EM" },
        { ProductType.CloudKeys, "EK" },
        { ProductType.IPWorksZip, "IZ" },
        { ProductType.IPWorksSSL, "IS" },
        { ProductType.IPWorksSSH, "IH" },
        { ProductType.IPWorksMQ, "IT" },
        { ProductType.IPWorksSFTP, "IF" },
        { ProductType.IPWorksOpenPGP, "IG" },
        { ProductType.IPWorksSNMP, "IN" },
        { ProductType.IPWorksIOT, "IO" },
        { ProductType.IPWorksBLE, "IL" },
        { ProductType.IPWorksEncrypt, "IE" },
    };
    public static string YearToString(ushort year) => ((char)(year - 1950)).ToString();

    public static string GetCode(ProductType type,
                                 ProductPlatform platform = ProductPlatform.All,
                                 ProductEditions edition = ProductEditions.DotNet,
                                 ushort year = 2024)
    {
        var parts = new[]
        {
            PRODUCT_PREFIX_MAP[type],
            ((char)platform).ToString(),
            ((char)edition).ToString(),
            YearToString(year)
        };
        return string.Join("", parts);
    }
}