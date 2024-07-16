using System.Text;

namespace nsoftwareKeygen;

public static class ProductSignatures
{
    public static Dictionary<ProductType, string> SEED_BANK = new();

    internal static void EncryptBuffer(byte[] buf, byte val1, byte val2, ProductType type)
    {
        SEED_BANK[type] = Encoding.ASCII.GetString(buf);
        for (var i = 0; i < 16; i++) buf[i] = (byte)(buf[i] + (val1 - 48) + (val2 - 48));
    }

    internal static byte[] GetSignature(ProductType type)
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
                break;
            case ProductType.IPWorksSMIME:
                break;
            case ProductType.IPWorksEncrypt:
                break;
            case ProductType.IPWorksOpenPGP:
                break;
            case ProductType.IPWorksSNMP:
                _IPWorksSNMP(buffer);
                break;
            case ProductType.IPWorksZip:
                _IPWorksZip(buffer);
                break;
            case ProductType.IPWorksAuth:
                break;
            case ProductType.IPWorksIPC:
                break;
            case ProductType.IPWorksMQ:
                break;
            case ProductType.IPWorksIOT:
                break;
            case ProductType.IPWorksSFTP:
                _IPWorksSFTP(buffer);
                break;
            case ProductType.IPWorksEDI:
                break;
            case ProductType.IPWorksEDITranslator:
                break;
            case ProductType.IPWorksBLE:
                break;
            case ProductType.IPWorks3DS:
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
            default:
                throw new ArgumentOutOfRangeException(nameof(type), type, null);
        }

        EncryptBuffer(buffer, 0x4e, 0x41, type);
        return buffer;
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