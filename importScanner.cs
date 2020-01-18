using System;
using System.IO;
using System.Text.RegularExpressions;
using Workshell.PE;
using Workshell.PE.Content;
using CommandLine;

namespace importscanner
{
    class ImportScanner
    {
        static bool CheckImport(Regex module, Regex function, ImportLibraryBase import)
        {
            // We are only looking for:
            //  - An import of 'api-ms-win-security-base.*.dll'
            //  - An exported function if that DLL called 'CveEventWrite'
            if (module.IsMatch(import.Name))
            {
                foreach (var importFunction in import.GetNamedFunctions())
                {
                    if (function.IsMatch(importFunction.Name))
                    {
                        return true;
                    }
                }
            }
            return false;
        }

        static void CheckPE(Regex module, Regex function, string filename)
        {
            bool found = false;
            try
            {
                PortableExecutableImage image = PortableExecutableImage.FromFile(filename);
                DelayedImports delayedImports = DelayedImports.Get(image);
                if (delayedImports != null)
                {
                    foreach (DelayedImportLibrary import in delayedImports)
                    {
                        found = CheckImport(module, function, import);
                        if (found)
                        {
                            break;
                        }
                    }
                }
                // If not in delayed imports, try explicit ones
                if (!found)
                {
                    Imports imports = Imports.Get(image);
                    if (imports != null)
                    {
                        foreach (ImportLibrary import in imports)
                        {
                            found = CheckImport(module, function, import);
                            if (found)
                            {
                                break;
                            }
                        }
                    }
                }
            }
            // If there's a bad DOS header or its not a valid PE, just ignore it
            catch (Workshell.PE.PortableExecutableImageException) { }

            if (found)
            {
                Console.WriteLine(filename);
            }
        }

        static void CheckDirectory(Regex module, Regex function, string directory)
        {
            try
            {
                foreach (string filename in Directory.GetFiles(directory))
                {
                    if (filename.ToLower().EndsWith(".dll") || filename.ToLower().EndsWith(".exe"))
                    {
                        CheckPE(module, function, filename);
                    }
                }

                // Check any sub directories
                foreach (string sub_dir in Directory.GetDirectories(directory))
                {
                    CheckDirectory(module, function, sub_dir);
                }
            }
            // If we can't access the file, don't worry about it
            catch (System.IO.IOException) { }
            catch (System.UnauthorizedAccessException) { }
        }

        public class CommandLineOptions
        {
            [Value(0, MetaName = "module", HelpText = "DLL to search for. Supports regex")]
            public string module { get; set; }

            [Value(1, MetaName = "function", HelpText = "Function in DLL to search for. Supports regex")]
            public string function { get; set; }

            [Value(2, MetaName = "directory", HelpText = "Base directory to search, or a single file", Default = "C:\\Windows\\System32")]
            public string directory { get; set; }
        }
        static void Main(string[] args)
        {
            CommandLine.Parser.Default.ParseArguments<CommandLineOptions>(args).WithParsed(opts =>
                {
                    if (opts.module == null || opts.function == null || opts.directory == null)
                    {
                        Console.WriteLine("Error: run 'importscanner.exe --help' for help");
                    }
                    else
                    {
                        Console.WriteLine("Searching for:");
                        Console.WriteLine($"  Module:   '{opts.module}'");
                        Console.WriteLine($"  Function: '{opts.function}'");
                        Regex module = new Regex(opts.module, RegexOptions.Compiled);
                        Regex function = new Regex(opts.function, RegexOptions.Compiled);
                        // Check if a Single file or a directory:
                        if (File.Exists(opts.directory) && !Directory.Exists(opts.directory))
                        {
                            Console.WriteLine($"  In file:  '{opts.directory}'");
                            Console.WriteLine("---------------------------------");
                            CheckPE(module, function, opts.directory);
                        }
                        else
                        {
                            Console.WriteLine($"  In dir:   '{opts.directory}'");
                            Console.WriteLine("---------------------------------");
                            CheckDirectory(module, function, opts.directory);
                        }
                    }
                });
        }
    }
}
