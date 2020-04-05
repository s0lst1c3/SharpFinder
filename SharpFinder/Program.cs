using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Net;
using System.DirectoryServices;
using System.Security.Principal;
using System.Security;
using System.DirectoryServices.ActiveDirectory;
using System.Runtime.InteropServices;
using System.Threading;
using System.Security.Permissions;
using System.Security.AccessControl;

namespace SharpFinder
{

    class SFOptions
    {


        public bool read_paths_from_file { get; set; }

        public string[] keywords;

        public string[] extensions;

        public string input_file;

        public string path;

        public bool exclude_hidden { get; set; }

        public bool grepable { get; set; }

        public bool acl_filter_writeable { get; set; }

        public bool acl_filter_readable { get; set; }

        public bool acl_filter_mode_and { get; set; }

        public void set_keywords(string[] my_keywords)
        {
            keywords = (string[])my_keywords.Clone();
        }

        public void set_extensions(string[] my_extensions)
        {
            extensions = (string[])my_extensions.Clone();
        }

        public void set_input_file(string my_input_file)
        {
            input_file = String.Copy(my_input_file);
            read_paths_from_file = true;
        }

        public void set_path(string my_path)
        {
            path = String.Copy(my_path);
        }

        public SFOptions(string my_path = ".\\",
            string my_input_file = "",
            string[] my_keywords = null,
            string[] my_extensions = null,
            bool my_exclude_hidden = false,
            bool my_grepable = false,
            bool my_acl_filter_readable = false,
            bool my_acl_filter_writeable = false,
            bool my_acl_filter_mode_and = false)
        {

            path = String.Copy(my_path);

            input_file = String.Copy(my_input_file);
            if (String.IsNullOrEmpty(input_file))
            {
                read_paths_from_file = false;
            }
            else
            {
                read_paths_from_file = true;
            }
            if (my_keywords == null)
            {

                keywords = null;
            }
            else
            {
                keywords = (string[])my_keywords.Clone();
            }

            if (my_extensions == null)
            {
                extensions = null;
            }
            else
            {
                extensions = (string[])my_extensions.Clone();
            }

            acl_filter_mode_and = my_acl_filter_mode_and;
            acl_filter_readable = my_acl_filter_readable;
            acl_filter_writeable = my_acl_filter_writeable;

            grepable = my_grepable;
        }
    }
    class Program
    {
        public static Semaphore MaxThreads { get; set; }

        [DllImport("Netapi32.dll", SetLastError = true)]
        public static extern int NetWkstaGetInfo(string servername, int level, out IntPtr bufptr);

        [DllImport("Netapi32.dll", SetLastError = true)]
        static extern int NetApiBufferFree(IntPtr Buffer);

        [DllImport("Netapi32.dll", CharSet = CharSet.Unicode)]
        private static extern int NetShareEnum(
            StringBuilder ServerName,
            int level,
            ref IntPtr bufPtr,
            uint prefmaxlen,
            ref int entriesread,
            ref int totalentries,
            ref int resume_handle
        );
        static IEnumerable<string> ReadPathsFromFile(string input_file)
        {
            using(System.IO.StreamReader input_handle = new System.IO.StreamReader(input_file))
            {

                int counter = 0;
                string line;

                while ((line = input_handle.ReadLine()) != null)
                {
                    yield return line;
                    counter++;
                }
            input_handle.Close();
            }
        }

        public static void PrintBanner()
        {

            Console.WriteLine("");
            Console.WriteLine(" _____ _                     ______ _           _           ");
            Console.WriteLine("/  ___| |                    |  ___(_)         | |          ");
            Console.WriteLine("\\ `--.| |__   __ _ _ __ _ __ | |_   _ _ __   __| | ___ _ __ ");
            Console.WriteLine(" `--. \\ '_ \\ / _` | '__| '_ \\|  _| | | '_ \\ / _` |/ _ \\ '__|");
            Console.WriteLine("/\\__/ / | | | (_| | |  | |_) | |   | | | | | (_| |  __/ |   ");
            Console.WriteLine("\\____/|_| |_|\\__,_|_|  | .__/\\_|   |_|_| |_|\\__,_|\\___|_| ");  
            Console.WriteLine("                       | |                                  ");
            Console.WriteLine("                       |_|                                  ");
            Console.WriteLine("                                                            ");
                                             

            Console.WriteLine("Version: 0.0.1");
            Console.WriteLine("Author: @s0lst1c3");
            Console.WriteLine("Contact: gabriel@specterops.io");
            Console.WriteLine("");
        }

        static IEnumerable<string> DirWalk(string path)
        {

            Queue<string> queue = new Queue<string>();
            queue.Enqueue(path);
            while (queue.Count > 0)
            {
                path = queue.Dequeue();
                try
                {
                    foreach (string subdir in System.IO.Directory.GetDirectories(path))
                    {
                        queue.Enqueue(subdir);
                    }
                }
                catch(Exception ex)
                {
                    if (ex.ToString().Contains("symbolic link cannot be followed")) {
                        continue;
                    }
                    if (ex.ToString().Contains("UnauthorizedAccessException")) {
                        continue;
                    }
                    else {
                        Console.WriteLine(ex);
                    }
                }
                string[] files = null;
                try
                {
                    files = System.IO.Directory.GetFiles(path);
                }
                catch(Exception ex)
                {
                    if (ex.ToString().Contains("UnauthorizedAccessException")) {
                        continue;
                    }
                    else {
                        Console.WriteLine(ex);
                    }
                }
                if (files != null)
                {
                    for (int i = 0; i< files.Length; i++)
                    {
                        yield return files[i];
                    }
                }
            }
        }

        public static bool FileHasPermission(string FilePath, FileSystemRights AccessRight)
        {

            if (string.IsNullOrEmpty(FilePath))
            {
                return false;
            }
            try
            {
                AuthorizationRuleCollection rules = System.IO.File.GetAccessControl(FilePath).GetAccessRules(true, true, typeof(System.Security.Principal.SecurityIdentifier));
                WindowsIdentity identity = WindowsIdentity.GetCurrent();

                foreach (FileSystemAccessRule rule in rules)
                {
                    if(identity.Groups.Contains(rule.IdentityReference) || identity.Owner.Equals(rule.IdentityReference))
                    {
                        if ((AccessRight & rule.FileSystemRights) > 0)
                        {
                            if (rule.AccessControlType == AccessControlType.Allow)
                            {
                                return true;
                            }
                        }
                    }
                }
            }
            catch
            {
            }
            return false;
        }
        public static void SearchFileShare(string path, SFOptions options)
        {
                    Console.WriteLine("[*] Searching for files in " + path);
                    foreach (string file in DirWalk(path))
                    {

                        bool keyword_match = false;
                        bool extension_match = false;
                        bool readable = false;
                        bool writeable = false;
                        bool acl_filter_match = false;
                        string keyword = "";
                        string extension = "";

                        if (options.keywords == null)
                        {
                            keyword_match = true;
                        }
                        else
                        {
                            for (int i = 0; i < options.keywords.Length; i++)
                            {
                                if (file.ToLower().Contains(options.keywords[i].ToLower()))
                                {
                                    keyword_match = true;
                                    keyword = options.keywords[i];
                                    break;
                                }
                            }
                        }

                        if (options.extensions == null)
                        {
                            extension_match = true;
                        }
                        else
                        {
                            for (int i = 0; i < options.extensions.Length; i++)
                            {
                                if (file.ToLower().EndsWith("."+options.extensions[i].ToLower()))
                                {
                                    extension_match = true;
                                    extension = options.extensions[i];
                                    break;
                                }
                            }
                        }

                        if ( !(keyword_match && extension_match) )
                        {
                            continue;
                        }
                        if (FileHasPermission(file, FileSystemRights.Read))
                        {
                            readable = true;
                        }
                        if (FileHasPermission(file, FileSystemRights.Write))
                        {
                            writeable = true;
                        }
                        if (options.acl_filter_readable && options.acl_filter_writeable)
                        {
                            if (options.acl_filter_mode_and && readable && writeable)
                            {
                                acl_filter_match = true;
                            }
                            else if (readable || writeable)
                            {
                                acl_filter_match = true;
                            }
                        }
                        else if ( !(options.acl_filter_readable || options.acl_filter_writeable) )
                        {

                            acl_filter_match = true;
                        }
                        else if (options.acl_filter_readable && readable)
                        {
                            acl_filter_match = true;
                        }
                        else if (options.acl_filter_writeable && writeable)
                        {
                            acl_filter_match = true;
                        }
                        if ( !acl_filter_match )
                        {
                            continue;
                        }
                        if ( options.exclude_hidden && System.IO.File.GetAttributes(file).HasFlag(System.IO.FileAttributes.Hidden))
                        {
                            continue;
                        }

                        if (options.grepable)
                        {
                            Console.WriteLine("SharpFinder," + keyword + "," + extension + "," + file + "," + readable + "," + writeable);
                        }
                        else
                        {
                            Console.WriteLine(file);
                            Console.WriteLine("\tKeyword: " + keyword);
                            Console.WriteLine("\tExtension: " + extension);
                            Console.WriteLine("\tWriteable: " + writeable);
                            Console.WriteLine("\tReadable: " + readable);
                        }
                    }
        }


        static void Main(string[] args)
        {

            PrintBanner();

            SFOptions options = new SFOptions();

            foreach (string a in args)
            {
                if (a.StartsWith("--path="))
                {
                    string[] components = a.Split('=');
                    options.set_path(components[1]);
                }
                else if (a.StartsWith("--input-file="))
                {
                    string[] components = a.Split('=');
                    options.set_input_file(components[1]);
                }
                else if (a.StartsWith("--keywords="))
                {
                    string[] components = a.Split('=');
                    string[] values = components[1].Split(',');
                    options.set_keywords(values);
                }
                else if (a.StartsWith("--extensions="))
                {
                    string[] components = a.Split('=');
                    string[] values = components[1].Split(',');
                    options.set_extensions(values);
                }
                else if (a.Equals("--exclude-hidden"))
                {
                    options.exclude_hidden = true;
                }
                else if (a.Equals("--acl-filter-mode-and"))
                {
                    options.acl_filter_mode_and = true;
                }
                else if (a.Equals("--readable"))
                {
                    options.acl_filter_readable = true;
                }
                else if (a.Equals("--writeable"))
                {
                    options.acl_filter_writeable = true;
                }
                else if (a.Equals("--grepable"))
                {
                    options.grepable = true;
                }
                else
                {
                    Console.WriteLine("Invalid flag: "+a);
                    return;
                }
            }

            if (options.read_paths_from_file)
            {
                foreach (string path in ReadPathsFromFile(options.input_file))
                {
                    SearchFileShare(path, options);
                }
            }
            else
            {
                SearchFileShare(options.path, options);
            }
        }
    }
}
