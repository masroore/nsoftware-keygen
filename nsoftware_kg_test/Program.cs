﻿using System.ComponentModel;
using System.Reflection;
using nsoftware.CloudKeys;
using nsoftware.CloudMail;
using nsoftware.CloudStorage;
using nsoftware.IPWorks;
using nsoftware.IPWorksSFTP;
using nsoftware.IPWorksSNMP;
using nsoftware.IPWorksSSL;
using nsoftware.IPWorksZip;
using nsoftware.SecureBlackbox;
using nsoftwareKeygen;
using static System.Console;


void LoadAndTestComponents(Assembly assembly, ProductType type)
{
    KeyGenerator.InitProductSignatures(type);
    var key = KeyGenerator.Generate(type);
    KeyGenerator.WriteLicenseFile(type, key);

    var components = FindDerivedTypes(assembly, typeof(Component)).ToList();
    foreach (var ct in components) {
        WriteLine("Activating " + ct.FullName);
        try {
            var obj = Activator.CreateInstance(ct, [key.RuntimeKey]);
            var about = obj.GetType().GetProperties().FirstOrDefault(o => o.Name == "About");
            if (about != null)
                WriteLine(about.GetValue(obj, null));
        }
        catch (MissingMethodException e) {
            // yawn...
        }
        catch (Exception e) {
            WriteLine(e);
            throw;
        }
    }
}

//h.init();

// assembly.GetTypes().Where(t => baseType.IsAssignableFrom(t) && t.FullName.ToLowerInvariant().StartsWith("nsoftware."));
IEnumerable<Type> FindDerivedTypes(Assembly assembly, Type baseType) =>
    assembly.GetTypes().Where(t => t.IsSubclassOf(baseType) && t.FullName.ToLowerInvariant().StartsWith("nsoftware."));

Assembly GetAssemblyByName(string name) => AppDomain.CurrentDomain.GetAssemblies().SingleOrDefault(x => x.GetName().Name == name);

void test_component<T>(ProductKey key) where T : new() // T : Type
{
    var obj = (T)Activator.CreateInstance(typeof(T), [key.RuntimeKey]);
    var about = obj.GetType().GetProperties().FirstOrDefault(o => o.Name == "About");
    if (about != null)
        WriteLine(about.GetValue(obj, null));
}

var asms = AppDomain.CurrentDomain.GetAssemblies().ToList();


LoadAndTestComponents(typeof(DNS).Assembly, ProductType.IPWorks);
LoadAndTestComponents(typeof(CloudStorage).Assembly, ProductType.CloudStorage);
LoadAndTestComponents(typeof(CloudMail).Assembly, ProductType.CloudMail);
LoadAndTestComponents(typeof(CertificateStorage).Assembly, ProductType.SecureBlackbox);
LoadAndTestComponents(typeof(AmazonKMS).Assembly, ProductType.CloudKeys);
LoadAndTestComponents(typeof(IPWorksZip).Assembly, ProductType.IPWorksZip);
LoadAndTestComponents(typeof(SSLServer).Assembly, ProductType.IPWorksSSL);
LoadAndTestComponents(typeof(IPWorksSFTP).Assembly, ProductType.IPWorksSFTP);
LoadAndTestComponents(typeof(IPWorksSNMP).Assembly, ProductType.IPWorksSNMP);


foreach (var kvp in ProductSignatures.SEED_BANK)
    WriteLine(kvp.Key + " = " + kvp.Value);

/*
M.ProductType = ProductType.IPWorks;
var key = KeyGenerator.Generate(ProductType.IPWorks);
KeyGenerator.WriteLicenseFile(M.ProductType, key);

M.n((byte)ProductType.IPWorks, typeof(DNS), key.RuntimeKey);
M.n((byte)ProductType.CloudStorage, typeof(DNS), key.RuntimeKey);
//test_component<DNS>(key);
*/