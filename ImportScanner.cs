using System;
using System.IO;
using Workshell.PE;
using Workshell.PE.Content;

namespace importscanner
{
    class ImportScanner
    {
        static bool check_import(ImportLibraryBase import)
        {
            // We are only looking for:
            //  - An import of 'api-ms-win-security-base.*.dll'
            //  - An exported function if that DLL called 'CveEventWrite'
            if (import.Name.Contains("api-ms-win-security-base"))
            {
                foreach (var function in import.GetNamedFunctions())
                {
                    if (function.Name == "CveEventWrite")
                    {
                        return true;
                    }
                }
            }
            return false;
        }

        static void check_pe(string filename)
        {
            bool found = false;
            try
            {
                PortableExecutableImage image = PortableExecutableImage.FromFile(filename);
                foreach (DelayedImportLibrary import in DelayedImports.Get(image))
                {
                    found = check_import(import);
                    if (found)
                    {
                        break;
                    }
                }

                // If not in delayed imports, try normal ones
                if (!found)
                {
                    foreach (ImportLibrary import in Imports.Get(image))
                    {
                        found = check_import(import);
                        if (found)
                        {
                            break;
                        }
                    }
                }
            }
            // NullReferenceException means it doesn't have any of those types of imports, ignore
            catch (System.NullReferenceException) { }
            // If there's a bad DOS header or its not a valid PE, just ignore it
            catch (Workshell.PE.PortableExecutableImageException) { }

            if (found)
            {
                Console.WriteLine(filename);
            }
        }

        static void check_dir(string dir)
        {
            try
            {
                foreach (string filename in Directory.GetFiles(dir, "*.dll"))
                {
                    check_pe(filename);
                }
                foreach (string filename in Directory.GetFiles(dir, "*.exe"))
                {
                    check_pe(filename);
                }

                foreach (string sub_dir in Directory.GetDirectories(dir))
                {
                    check_dir(sub_dir);
                }
            }
            // If we can't access the file, don't worry about it
            catch (System.UnauthorizedAccessException) { }
        }

        static void Main(string[] args)
        {
            string base_path = "C:\\Windows\\System32";
            if (args.Length > 0)
            {
                base_path = args[0];
            }

            check_dir(base_path);
        }
    }
}
