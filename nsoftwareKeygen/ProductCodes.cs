namespace nsoftwareKeygen;

public static class ProductCodes
{
    private static readonly Dictionary<ProductType, string> PRODUCT_PREFIX_MAP = new()
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
        { ProductType.IPWorksDTLS, "ID" },
        { ProductType.CloudIdentity, "EI" },
        { ProductType.IPWorks3DS, "TS" },
        { ProductType.IPWorksEDI, "BE" },
        { ProductType.IPWorksEDITranslator, "BE" },
        { ProductType.IPWorksAuth, "IA" },
        { ProductType.CloudBackup, "EB" },
        { ProductType.InPay, "BP" },
        { ProductType.IPWorksIPC, "IP" },
        { ProductType.IPWorksSMIME, "IM" }
    };

    public static string YearToString(short year) => ((char)(year - 1950)).ToString();

    public static short GetLastBuildYear(ProductType type)
    {
        return type switch
        {
            ProductType.InPay          => 2020,
            ProductType.IPWorksSMIME   => 2022,
            ProductType.IPWorksEncrypt => 2022,
            ProductType.IPWorksOpenPGP => 2022,
            ProductType.IPWorksIPC     => 2022,
            ProductType.IPWorksMQ      => 2022,
            ProductType.IPWorksIOT     => 2022,
            ProductType.IPWorksBLE     => 2022,
            _                          => 2024
        };
    }

    public static string GetCode(ProductType type,
                                 ProductPlatform platform = ProductPlatform.All,
                                 ProductEditions edition = ProductEditions.DotNet,
                                 short year = -1)
    {
        var parts = new[]
        {
            PRODUCT_PREFIX_MAP[type],
            ((char)platform).ToString(),
            ((char)edition).ToString(),
            YearToString(year < 0 ? GetLastBuildYear(type) : year)
        };
        return string.Join("", parts);
    }
}