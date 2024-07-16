using System.Text;

namespace nsoftwareKeygen;

public static class ProductSignatures
{
    internal static Dictionary<ProductType, string> SIGNATURES_DECRYPTED = new();

    internal static readonly Dictionary<ProductType, string> SIGNATURES = new()
    {
        { ProductType.IPWorks, "FiNAID1tuTqtudJF" },
        { ProductType.CloudStorage, "7xuG03vZuusunKXn" },
        { ProductType.CloudMail, "aaIwb2r9Sg2UQhjz" },
        { ProductType.CloudKeys, "Rrgrr8h38YMh9BBl" },
        { ProductType.SecureBlackbox, "1kFv0MWjHBk2joN7" },
        { ProductType.IPWorksZip, "P9zlFqBfuWepPMyI" },
        { ProductType.IPWorksSSL, "SkO0yiYEwyXZtrVV" },
        { ProductType.IPWorksSFTP, "eBvbybmJQnaDMfVs" },
        { ProductType.IPWorksSNMP, "a9PkfFmRoiZfhm7u" },
        { ProductType.IPWorks3DS, "O1jcOGRjlntZh2ZZ" },
        { ProductType.IPWorksBLE, "i1VVVPYTlShmvLWz" },
        { ProductType.IPWorksAuth, "qgnC0zP71tw32KtA" },
        { ProductType.IPWorksEDI, "PgZERBCMKHsE32Ty" },
        { ProductType.IPWorksEDITranslator, "0BMmEnhYRK1AZcLd" },
        { ProductType.IPWorksDTLS, "a8ZSG8NxfQOUNbcr" },
        { ProductType.IPWorksIPC, "Akd3JE7AXt7HLAwC" },
        { ProductType.IPWorksMQ, "MDPIQ2AzH3nX9GOQ" },
        { ProductType.IPWorksOpenPGP, "LlamoxyQ7UGSUUqV" },
        { ProductType.InPay, "mPXSJWWZ3REyFD0n" },
        { ProductType.IPWorksIOT, "qXw0ucW0k3DpQBzU" },
        { ProductType.IPWorksSMIME, "BT1jqFJuzKSS8wiP" },
        { ProductType.IPWorksEncrypt, "Xx1IDKMrmkhuYotg" },
        { ProductType.IPWorksSSH, "1FiPloDeYknbzbMc" },
        { ProductType.CloudBackup, "" },
        { ProductType.CloudIdentity, "" }
    };


    internal static byte[] GetSignature(ProductType type)
    {
        byte[] buffer = [];
        var signature = SIGNATURES[type];

        if (!string.IsNullOrEmpty(signature)) {
            buffer = Encoding.ASCII.GetBytes(signature);
            EncryptBuffer(buffer, 0x4e, 0x41, type);
        }

        return buffer;
    }

    internal static void EncryptBuffer(byte[] buf, byte val1, byte val2, ProductType type)
    {
        SIGNATURES_DECRYPTED[type] = Encoding.ASCII.GetString(buf);
        for (var i = 0; i < 16; i++) buf[i] = (byte)(buf[i] + (val1 - 48) + (val2 - 48));
    }

    internal static byte[] GetSignatureFromBytes(ProductType type)
    {
        var buffer = new byte[16];
        switch (type) {
            case ProductType.IPWorks:
                _IPWorks(buffer);
                break;
            case ProductType.CloudStorage:
                _CloudStorage(buffer);
                break;
            case ProductType.IPWorksSSL:
                _IPWorksSSL(buffer);
                break;
            case ProductType.IPWorksSSH:
                _IPWorksSSH(buffer);
                break;
            case ProductType.IPWorksSMIME:
                _IPWorksSMIME(buffer);
                break;
            case ProductType.IPWorksEncrypt:
                _IPWorksEncrypt(buffer);
                break;
            case ProductType.IPWorksOpenPGP:
                _IPWorksOpenPGP(buffer);
                break;
            case ProductType.IPWorksSNMP:
                _IPWorksSNMP(buffer);
                break;
            case ProductType.IPWorksZip:
                _IPWorksZip(buffer);
                break;
            case ProductType.IPWorksAuth:
                _IPWorksAuth(buffer);
                break;
            case ProductType.IPWorksIPC:
                _IPWorksIPC(buffer);
                break;
            case ProductType.IPWorksMQ:
                _IPWorksMQ(buffer);
                break;
            case ProductType.IPWorksIOT:
                _IPWorksIOT(buffer);
                break;
            case ProductType.IPWorksSFTP:
                _IPWorksSFTP(buffer);
                break;
            case ProductType.IPWorksEDI:
                _IPWorksEDI(buffer);
                break;
            case ProductType.IPWorksEDITranslator:
                _IPWorksEDITranslator(buffer);
                break;
            case ProductType.IPWorksBLE:
                _IPWorksBLE(buffer);
                break;
            case ProductType.IPWorks3DS:
                _IPWorks3DS(buffer);
                break;
            case ProductType.CloudMail:
                _CloudMail(buffer);
                break;
            case ProductType.CloudKeys:
                _CloudKeys(buffer);
                break;
            case ProductType.SecureBlackbox:
                _SecureBlackbox(buffer);
                break;
            case ProductType.IPWorksDTLS:
                _IPWorksDTLS(buffer);
                break;
            case ProductType.CloudIdentity:
                _CloudIdentity(buffer);
                break;
            case ProductType.CloudBackup:
                _CloudBackup(buffer);
                break;
            case ProductType.InPay:
                _InPay(buffer);
                break;
            default:
                throw new ArgumentOutOfRangeException(nameof(type), type, null);
        }

        EncryptBuffer(buffer, 0x4e, 0x41, type);
        return buffer;
    }

    private static void _IPWorksAuth(byte[] buffer1)
    {
        var num = 0;
        buffer1[num++] = 0x71;
        buffer1[num++] = 0x67;
        buffer1[num++] = 110;
        buffer1[num++] = 0x43;
        buffer1[num++] = 0x30;
        buffer1[num++] = 0x7a;
        buffer1[num++] = 80;
        buffer1[num++] = 0x37;
        buffer1[num++] = 0x31;
        buffer1[num++] = 0x74;
        buffer1[num++] = 0x77;
        buffer1[num++] = 0x33;
        buffer1[num++] = 50;
        buffer1[num++] = 0x4b;
        buffer1[num++] = 0x74;
        buffer1[num++] = 0x41;
    }

    private static void _IPWorksBLE(byte[] buffer1)
    {
        var num = 0;
        buffer1[num++] = 0x69;
        buffer1[num++] = 0x31;
        buffer1[num++] = 0x56;
        buffer1[num++] = 0x56;
        buffer1[num++] = 0x56;
        buffer1[num++] = 80;
        buffer1[num++] = 0x59;
        buffer1[num++] = 0x54;
        buffer1[num++] = 0x6c;
        buffer1[num++] = 0x53;
        buffer1[num++] = 0x68;
        buffer1[num++] = 0x6d;
        buffer1[num++] = 0x76;
        buffer1[num++] = 0x4c;
        buffer1[num++] = 0x57;
        buffer1[num++] = 0x7a;
    }

    private static void _IPWorksEDITranslator(byte[] buffer1)
    {
        var num = 0;
        buffer1[num++] = 0x30;
        buffer1[num++] = 0x42;
        buffer1[num++] = 0x4d;
        buffer1[num++] = 0x6d;
        buffer1[num++] = 0x45;
        buffer1[num++] = 110;
        buffer1[num++] = 0x68;
        buffer1[num++] = 0x59;
        buffer1[num++] = 0x52;
        buffer1[num++] = 0x4b;
        buffer1[num++] = 0x31;
        buffer1[num++] = 0x41;
        buffer1[num++] = 90;
        buffer1[num++] = 0x63;
        buffer1[num++] = 0x4c;
        buffer1[num++] = 100;
    }

    private static void _IPWorksEDI(byte[] buffer1)
    {
        var num = 0;
        buffer1[num++] = 80;
        buffer1[num++] = 0x67;
        buffer1[num++] = 90;
        buffer1[num++] = 0x45;
        buffer1[num++] = 0x52;
        buffer1[num++] = 0x42;
        buffer1[num++] = 0x43;
        buffer1[num++] = 0x4d;
        buffer1[num++] = 0x4b;
        buffer1[num++] = 0x48;
        buffer1[num++] = 0x73;
        buffer1[num++] = 0x45;
        buffer1[num++] = 0x33;
        buffer1[num++] = 50;
        buffer1[num++] = 0x54;
        buffer1[num++] = 0x79;
    }

    private static void _IPWorks3DS(byte[] buffer1)
    {
        var num = 0;
        buffer1[num++] = 0x4f;
        buffer1[num++] = 0x31;
        buffer1[num++] = 0x6a;
        buffer1[num++] = 0x63;
        buffer1[num++] = 0x4f;
        buffer1[num++] = 0x47;
        buffer1[num++] = 0x52;
        buffer1[num++] = 0x6a;
        buffer1[num++] = 0x6c;
        buffer1[num++] = 110;
        buffer1[num++] = 0x74;
        buffer1[num++] = 90;
        buffer1[num++] = 0x68;
        buffer1[num++] = 50;
        buffer1[num++] = 90;
        buffer1[num++] = 90;
    }

    private static void _IPWorksDTLS(byte[] buffer1)
    {
        var num = 0;
        buffer1[num++] = 0x61;
        buffer1[num++] = 0x38;
        buffer1[num++] = 90;
        buffer1[num++] = 0x53;
        buffer1[num++] = 0x47;
        buffer1[num++] = 0x38;
        buffer1[num++] = 0x4e;
        buffer1[num++] = 120;
        buffer1[num++] = 0x66;
        buffer1[num++] = 0x51;
        buffer1[num++] = 0x4f;
        buffer1[num++] = 0x55;
        buffer1[num++] = 0x4e;
        buffer1[num++] = 0x62;
        buffer1[num++] = 0x63;
        buffer1[num++] = 0x72;
    }

    private static void _IPWorksIOT(byte[] buffer1)
    {
        var num = 0;
        buffer1[num++] = 0x71;
        buffer1[num++] = 0x58;
        buffer1[num++] = 0x77;
        buffer1[num++] = 0x30;
        buffer1[num++] = 0x75;
        buffer1[num++] = 0x63;
        buffer1[num++] = 0x57;
        buffer1[num++] = 0x30;
        buffer1[num++] = 0x6b;
        buffer1[num++] = 0x33;
        buffer1[num++] = 0x44;
        buffer1[num++] = 0x70;
        buffer1[num++] = 0x51;
        buffer1[num++] = 0x42;
        buffer1[num++] = 0x7a;
        buffer1[num++] = 0x55;
    }

    private static void _IPWorksMQ(byte[] buffer1)
    {
        var num = 0;
        buffer1[num++] = 0x4d;
        buffer1[num++] = 0x44;
        buffer1[num++] = 80;
        buffer1[num++] = 0x49;
        buffer1[num++] = 0x51;
        buffer1[num++] = 50;
        buffer1[num++] = 0x41;
        buffer1[num++] = 0x7a;
        buffer1[num++] = 0x48;
        buffer1[num++] = 0x33;
        buffer1[num++] = 110;
        buffer1[num++] = 0x58;
        buffer1[num++] = 0x39;
        buffer1[num++] = 0x47;
        buffer1[num++] = 0x4f;
        buffer1[num++] = 0x51;
    }

    private static void _IPWorksIPC(byte[] buffer1)
    {
        var num = 0;
        buffer1[num++] = 0x41;
        buffer1[num++] = 0x6b;
        buffer1[num++] = 100;
        buffer1[num++] = 0x33;
        buffer1[num++] = 0x4a;
        buffer1[num++] = 0x45;
        buffer1[num++] = 0x37;
        buffer1[num++] = 0x41;
        buffer1[num++] = 0x58;
        buffer1[num++] = 0x74;
        buffer1[num++] = 0x37;
        buffer1[num++] = 0x48;
        buffer1[num++] = 0x4c;
        buffer1[num++] = 0x41;
        buffer1[num++] = 0x77;
        buffer1[num++] = 0x43;
    }

    private static void _IPWorksSSH(byte[] buffer1)
    {
        var num = 0;
        buffer1[num++] = 0x31;
        buffer1[num++] = 70;
        buffer1[num++] = 0x69;
        buffer1[num++] = 80;
        buffer1[num++] = 0x6c;
        buffer1[num++] = 0x6f;
        buffer1[num++] = 0x44;
        buffer1[num++] = 0x65;
        buffer1[num++] = 0x59;
        buffer1[num++] = 0x6b;
        buffer1[num++] = 110;
        buffer1[num++] = 0x62;
        buffer1[num++] = 0x7a;
        buffer1[num++] = 0x62;
        buffer1[num++] = 77;
        buffer1[num++] = 0x63;
    }

    private static void _CloudBackup(byte[] buffer1)
    {
        var num = 0;
        // beta product. licensing not yet implemented
    }

    private static void _CloudIdentity(byte[] buffer1)
    {
        var num = 0;
        // beta product. licensing not yet implemented
    }

    private static void _IPWorksSMIME(byte[] buffer1)
    {
        var num = 0;
        buffer1[num++] = 0x42;
        buffer1[num++] = 0x54;
        buffer1[num++] = 0x31;
        buffer1[num++] = 0x6a;
        buffer1[num++] = 0x71;
        buffer1[num++] = 70;
        buffer1[num++] = 0x4a;
        buffer1[num++] = 0x75;
        buffer1[num++] = 0x7a;
        buffer1[num++] = 0x4b;
        buffer1[num++] = 0x53;
        buffer1[num++] = 0x53;
        buffer1[num++] = 0x38;
        buffer1[num++] = 0x77;
        buffer1[num++] = 0x69;
        buffer1[num++] = 80;
    }

    private static void _IPWorksOpenPGP(byte[] buffer1)
    {
        var num = 0;
        buffer1[num++] = 0x4c;
        buffer1[num++] = 0x6c;
        buffer1[num++] = 0x61;
        buffer1[num++] = 0x6d;
        buffer1[num++] = 0x6f;
        buffer1[num++] = 120;
        buffer1[num++] = 0x79;
        buffer1[num++] = 0x51;
        buffer1[num++] = 0x37;
        buffer1[num++] = 0x55;
        buffer1[num++] = 0x47;
        buffer1[num++] = 0x53;
        buffer1[num++] = 0x55;
        buffer1[num++] = 0x55;
        buffer1[num++] = 0x71;
        buffer1[num++] = 0x56;
    }

    private static void _IPWorksEncrypt(byte[] buffer1)
    {
        var num = 0;
        buffer1[num++] = 0x58;
        buffer1[num++] = 120;
        buffer1[num++] = 0x31;
        buffer1[num++] = 0x49;
        buffer1[num++] = 0x44;
        buffer1[num++] = 0x4b;
        buffer1[num++] = 0x4d;
        buffer1[num++] = 0x72;
        buffer1[num++] = 0x6d;
        buffer1[num++] = 0x6b;
        buffer1[num++] = 0x68;
        buffer1[num++] = 0x75;
        buffer1[num++] = 0x59;
        buffer1[num++] = 0x6f;
        buffer1[num++] = 0x74;
        buffer1[num++] = 0x67;
    }

    private static void _InPay(byte[] buffer1)
    {
        var num = 0;
        buffer1[num++] = 0x6d;
        buffer1[num++] = 80;
        buffer1[num++] = 0x58;
        buffer1[num++] = 0x53;
        buffer1[num++] = 0x4a;
        buffer1[num++] = 0x57;
        buffer1[num++] = 0x57;
        buffer1[num++] = 90;
        buffer1[num++] = 0x33;
        buffer1[num++] = 0x52;
        buffer1[num++] = 0x45;
        buffer1[num++] = 0x79;
        buffer1[num++] = 70;
        buffer1[num++] = 0x44;
        buffer1[num++] = 0x30;
        buffer1[num++] = 110;
    }

    private static void _IPWorksSNMP(byte[] buffer1)
    {
        var num = 0;
        buffer1[num++] = 0x61;
        buffer1[num++] = 0x39;
        buffer1[num++] = 80;
        buffer1[num++] = 0x6b;
        buffer1[num++] = 0x66;
        buffer1[num++] = 70;
        buffer1[num++] = 0x6d;
        buffer1[num++] = 0x52;
        buffer1[num++] = 0x6f;
        buffer1[num++] = 0x69;
        buffer1[num++] = 90;
        buffer1[num++] = 0x66;
        buffer1[num++] = 0x68;
        buffer1[num++] = 0x6d;
        buffer1[num++] = 0x37;
        buffer1[num++] = 0x75;
    }

    private static void _IPWorksSFTP(byte[] buffer1)
    {
        var num = 0;
        buffer1[num++] = 0x65;
        buffer1[num++] = 0x42;
        buffer1[num++] = 0x76;
        buffer1[num++] = 0x62;
        buffer1[num++] = 0x79;
        buffer1[num++] = 0x62;
        buffer1[num++] = 0x6d;
        buffer1[num++] = 0x4a;
        buffer1[num++] = 0x51;
        buffer1[num++] = 110;
        buffer1[num++] = 0x61;
        buffer1[num++] = 0x44;
        buffer1[num++] = 0x4d;
        buffer1[num++] = 0x66;
        buffer1[num++] = 0x56;
        buffer1[num++] = 0x73;
    }

    private static void _CloudStorage(byte[] buffer)
    {
        var num = 0;
        buffer[num++] = 0x37;
        buffer[num++] = 120;
        buffer[num++] = 0x75;
        buffer[num++] = 0x47;
        buffer[num++] = 0x30;
        buffer[num++] = 0x33;
        buffer[num++] = 0x76;
        buffer[num++] = 90;
        buffer[num++] = 0x75;
        buffer[num++] = 0x75;
        buffer[num++] = 0x73;
        buffer[num++] = 0x75;
        buffer[num++] = 110;
        buffer[num++] = 0x4b;
        buffer[num++] = 0x58;
        buffer[num++] = 110;
    }

    private static void _IPWorks(byte[] buffer1)
    {
        var num = 0;
        buffer1[num++] = 70;
        buffer1[num++] = 0x69;
        buffer1[num++] = 0x4e;
        buffer1[num++] = 0x41;
        buffer1[num++] = 0x49;
        buffer1[num++] = 0x44;
        buffer1[num++] = 0x31;
        buffer1[num++] = 0x74;
        buffer1[num++] = 0x75;
        buffer1[num++] = 0x54;
        buffer1[num++] = 0x71;
        buffer1[num++] = 0x74;
        buffer1[num++] = 0x75;
        buffer1[num++] = 100;
        buffer1[num++] = 0x4a;
        buffer1[num++] = 70;
    }

    private static void _CloudMail(byte[] buffer1)
    {
        var num = 0;
        buffer1[num++] = 0x61;
        buffer1[num++] = 0x61;
        buffer1[num++] = 0x49;
        buffer1[num++] = 0x77;
        buffer1[num++] = 0x62;
        buffer1[num++] = 50;
        buffer1[num++] = 0x72;
        buffer1[num++] = 0x39;
        buffer1[num++] = 0x53;
        buffer1[num++] = 0x67;
        buffer1[num++] = 50;
        buffer1[num++] = 0x55;
        buffer1[num++] = 0x51;
        buffer1[num++] = 0x68;
        buffer1[num++] = 0x6a;
        buffer1[num++] = 0x7a;
    }

    private static void _CloudKeys(byte[] buffer1)
    {
        var num = 0;
        buffer1[num++] = 0x52;
        buffer1[num++] = 0x72;
        buffer1[num++] = 0x67;
        buffer1[num++] = 0x72;
        buffer1[num++] = 0x72;
        buffer1[num++] = 0x38;
        buffer1[num++] = 0x68;
        buffer1[num++] = 0x33;
        buffer1[num++] = 0x38;
        buffer1[num++] = 0x59;
        buffer1[num++] = 0x4d;
        buffer1[num++] = 0x68;
        buffer1[num++] = 0x39;
        buffer1[num++] = 0x42;
        buffer1[num++] = 0x42;
        buffer1[num++] = 0x6c;
    }

    private static void _SecureBlackbox(byte[] buffer1)
    {
        var num = 0;
        buffer1[num++] = 0x31;
        buffer1[num++] = 0x6b;
        buffer1[num++] = 70;
        buffer1[num++] = 0x76;
        buffer1[num++] = 0x30;
        buffer1[num++] = 0x4d;
        buffer1[num++] = 0x57;
        buffer1[num++] = 0x6a;
        buffer1[num++] = 0x48;
        buffer1[num++] = 0x42;
        buffer1[num++] = 0x6b;
        buffer1[num++] = 50;
        buffer1[num++] = 0x6a;
        buffer1[num++] = 0x6f;
        buffer1[num++] = 0x4e;
        buffer1[num++] = 0x37;
    }

    private static void _IPWorksZip(byte[] buffer1)
    {
        var num = 0;
        buffer1[num++] = 80;
        buffer1[num++] = 0x39;
        buffer1[num++] = 0x7a;
        buffer1[num++] = 0x6c;
        buffer1[num++] = 70;
        buffer1[num++] = 0x71;
        buffer1[num++] = 0x42;
        buffer1[num++] = 0x66;
        buffer1[num++] = 0x75;
        buffer1[num++] = 0x57;
        buffer1[num++] = 0x65;
        buffer1[num++] = 0x70;
        buffer1[num++] = 80;
        buffer1[num++] = 0x4d;
        buffer1[num++] = 0x79;
        buffer1[num++] = 0x49;
    }

    private static void _IPWorksSSL(byte[] buffer1)
    {
        var num = 0;
        buffer1[num++] = 0x53;
        buffer1[num++] = 0x6b;
        buffer1[num++] = 0x4f;
        buffer1[num++] = 0x30;
        buffer1[num++] = 0x79;
        buffer1[num++] = 0x69;
        buffer1[num++] = 0x59;
        buffer1[num++] = 0x45;
        buffer1[num++] = 0x77;
        buffer1[num++] = 0x79;
        buffer1[num++] = 0x58;
        buffer1[num++] = 90;
        buffer1[num++] = 0x74;
        buffer1[num++] = 0x72;
        buffer1[num++] = 0x56;
        buffer1[num++] = 0x56;
    }
}