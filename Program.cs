using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Net;
using System.DirectoryServices;
using System.Security.Principal;
using System.DirectoryServices.ActiveDirectory;
using System.Runtime.InteropServices;
using System.IO;
using System.Security.AccessControl;

namespace ShareShooter
{
    class Program
    {
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

        [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
        public struct SHARE_INFO_0
        {
            public string shi0_netname;
        }

        [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
        public struct SHARE_INFO_1
        {
            public string shi1_netname;
            public uint shi1_type;
            public string shi1_remark;
            public SHARE_INFO_1(string sharename, uint sharetype, string remark)
            {
                this.shi1_netname = sharename;
                this.shi1_type = sharetype;
                this.shi1_remark = remark;
            }
            public override string ToString()
            {
                return shi1_netname;
            }
        }

        const uint MAX_PREFERRED_LENGTH = 0xFFFFFFFF;
        const int NERR_Success = 0;

        private enum NetError : uint
        {
            NERR_Success = 0,
            NERR_BASE = 2100,
            NERR_UnknownDevDir = (NERR_BASE + 16),
            NERR_DuplicateShare = (NERR_BASE + 18),
            NERR_BufTooSmall = (NERR_BASE + 23),
        }

        private enum SHARE_TYPE : uint
        {
            STYPE_DISKTREE = 0,
            STYPE_PRINTQ = 1,
            STYPE_DEVICE = 2,
            STYPE_IPC = 3,
            STYPE_SPECIAL = 0x80000000,
        }


        static List<string> writablePaths = new List<string>();

        public static SHARE_INFO_1[] EnumNetShares(string Server)
        {
            List<SHARE_INFO_1> ShareInfos = new List<SHARE_INFO_1>();
            int entriesread = 0;
            int totalentries = 0;
            int resume_handle = 0;
            int nStructSize = Marshal.SizeOf(typeof(SHARE_INFO_1));
            IntPtr bufPtr = IntPtr.Zero;
            StringBuilder server = new StringBuilder(Server);
            int ret = NetShareEnum(server, 1, ref bufPtr, MAX_PREFERRED_LENGTH, ref entriesread, ref totalentries, ref resume_handle);
            if (ret == NERR_Success)
            {
                IntPtr currentPtr = bufPtr;
                for (int i = 0; i < entriesread; i++)
                {
                    SHARE_INFO_1 shi1 = (SHARE_INFO_1)Marshal.PtrToStructure(currentPtr, typeof(SHARE_INFO_1));
                    ShareInfos.Add(shi1);
                    currentPtr += nStructSize;
                }
                NetApiBufferFree(bufPtr);
                return ShareInfos.ToArray();
            }
            else
            {
                ShareInfos.Add(new SHARE_INFO_1("ERROR=" + ret.ToString(), 10, string.Empty));
                return ShareInfos.ToArray();
            }
        }


        
        public static List<DomainController> GetDomainControllers()
        {
            List<DomainController> domainControllers = new List<DomainController>();
            try
            {
                Domain domain = Domain.GetCurrentDomain();
                foreach (DomainController dc in domain.DomainControllers)
                {
                    domainControllers.Add(dc);
                }
            }
            catch { }
            return domainControllers;
        }

        public static void GetComputerAddresses(List<string> computers)
        {
            foreach (string computer in computers)
            {
                IPAddress[] ips = System.Net.Dns.GetHostAddresses(computer);
                foreach (IPAddress ip in ips)
                {
                    if (!ip.ToString().Contains(":"))
                    {
                        Console.WriteLine("{0}: {1}", computer, ip);
                    }
                }
            }
        }

        public static List<string> GetComputers()
        {
            List<string> computerNames = new List<string>();
            List<DomainController> dcs = GetDomainControllers();
            if (dcs.Count > 0)
            {
                try
                {
                    Domain domain = Domain.GetCurrentDomain();
                    //domain.
                    string currentUser = WindowsIdentity.GetCurrent().Name.Split('\\')[1];


                    using (DirectoryEntry entry = new DirectoryEntry(String.Format("LDAP://{0}", dcs[0])))
                    {
                        using (DirectorySearcher mySearcher = new DirectorySearcher(entry))
                        {
                            mySearcher.Filter = ("(objectClass=computer)");

                            // No size limit, reads all objects
                            mySearcher.SizeLimit = 0;

                            // Read data in pages of 250 objects. Make sure this value is below the limit configured in your AD domain (if there is a limit)
                            mySearcher.PageSize = 250;

                            // Let searcher know which properties are going to be used, and only load those
                            mySearcher.PropertiesToLoad.Add("name");

                            foreach (SearchResult resEnt in mySearcher.FindAll())
                            {
                                // Note: Properties can contain multiple values.
                                if (resEnt.Properties["name"].Count > 0)
                                {
                                    string computerName = (string)resEnt.Properties["name"][0];
                                    computerNames.Add(computerName);
                                }
                            }
                        }
                    }
                }
                catch { }
            }
            else
            {
                Console.WriteLine("ERROR: Could not get a list of Domain Controllers.");
            }
            return computerNames;
        }

        /// <summary>
        /// Test a directory for create file access permissions
        /// </summary>
        /// <param name="DirectoryPath">Full path to directory </param>
        /// <param name="AccessRight">File System right tested</param>
        /// <returns>State [bool]</returns>
        public static bool DirectoryHasPermission(string DirectoryPath, FileSystemRights AccessRight)
        {
            if (string.IsNullOrEmpty(DirectoryPath)) return false;

            try
            {
                AuthorizationRuleCollection rules = Directory.GetAccessControl(DirectoryPath).GetAccessRules(true, true, typeof(System.Security.Principal.SecurityIdentifier));
                WindowsIdentity identity = WindowsIdentity.GetCurrent();

                foreach (FileSystemAccessRule rule in rules)
                {
                    if (identity.Groups.Contains(rule.IdentityReference))
                    {
                        if ((AccessRight & rule.FileSystemRights) == AccessRight)
                        {
                            if (rule.AccessControlType == AccessControlType.Allow)
                                return true;
                        }
                    }
                }
            }
            catch { }
            return false;
        }

        public static void GetShares(List<string> computers)
        {

            List<string> readableShares = new List<string>();
            List<string> writableShares = new List<string>();
            List<string> unreadableShares = new List<string>();
            List<string> readableNotWritableShares = new List<string>();


            string[] errors = { "ERROR=53", "ERROR=5" };
            foreach(string computer in computers)
            {
                SHARE_INFO_1[] computerShares = EnumNetShares(computer);
                if (computerShares.Length > 0)
                {
                    

                    foreach(SHARE_INFO_1 share in computerShares)
                    {
                        try
                        {
                            // check if path is readable
                            string path = String.Format("\\\\{0}\\{1}", computer, share.shi1_netname);
                            var files = System.IO.Directory.GetFiles(path);
                            readableShares.Add(share.shi1_netname);


                            try
                            {
                                // check if path is writable
                                // Attempt to get a list of security permissions from the folder. 
                                // This will raise an exception if the path is read only or do not have access to view the permissions. 
                                System.Security.AccessControl.DirectorySecurity ds = Directory.GetAccessControl(path);
                                writableShares.Add(share.shi1_netname);
                                writablePaths.Add(path);
                                /*if (DirectoryHasPermission(path, FileSystemRights.Write)) { // alternative method of determining write access
                                    writableShares.Add(share.shi1_netname);
                                }*/

                            }
                            catch (Exception e)
                            {
                                readableNotWritableShares.Add(share.shi1_netname);
                            }
                            
                            
                        }
                        catch
                        {
                            if (!errors.Contains(share.shi1_netname))
                            {
                                unreadableShares.Add(share.shi1_netname);
                            }
                        }
                    }
                    if (unreadableShares.Count > 0 || readableShares.Count > 0 || writableShares.Count > 0) 
                    {
                        Console.WriteLine("Shares for {0}:", computer);
                        if (unreadableShares.Count > 0)
                        {
                            Console.WriteLine("\t[--- Unreadable Shares ---]");
                            foreach (string share in unreadableShares)
                            {
                                Console.WriteLine("\t\t{0}", share);
                            }
                        }
                        if (readableShares.Count > 0)
                        {
                            Console.WriteLine("\t[--- Listable Shares ---]");
                            foreach (string share in readableShares)
                            {
                                Console.WriteLine("\t\t{0}", share);
                            }
                        }
                        if (writableShares.Count > 0)
                        {
                            Console.WriteLine("\t[--- Writable Shares ---]");
                            foreach (string share in writableShares)
                            {
                                Console.WriteLine("\t\t{0}", share);
                            }
                        }
                    }
                }
            }
        }

        public static bool isURLExist(string url)
        {
            try
            {
                WebRequest req = WebRequest.Create(url);

                WebResponse res = req.GetResponse();

                return true;
            }
            catch (WebException ex)
            {
                //Console.WriteLine(ex.Message);
                if (ex.Message.Contains("remote name could not be resolved"))
                {
                    return false;
                }
            }

            return false;
        }

        // Scan the writable shares for files with web extensions
        public static void findLiveWebFiles()
        {
            writablePaths.Add("C:\\Users\\Karp\\Downloads\\testShare");
            List<string> validURLs = new List<string>();

            foreach (string aPath in writablePaths)
            {


                // Check non case sensitive web file extensions
                // I used the ones from this website: https://fileinfo.com/filetypes/web
                IEnumerable<string> e = Directory.GetFiles(aPath, "*.*", SearchOption.AllDirectories).Where(s => s.ToUpper().EndsWith(".A4P") || s.ToUpper().EndsWith(".A5W") || s.ToUpper().EndsWith(".ADR") || s.ToUpper().EndsWith(".AEX") || s.ToUpper().EndsWith(".ALX") || s.ToUpper().EndsWith(".AN") || s.ToUpper().EndsWith(".AP") || s.ToUpper().EndsWith(".APPCACHE") || s.ToUpper().EndsWith(".ARO") || s.ToUpper().EndsWith(".ASA") || s.ToUpper().EndsWith(".ASAX") || s.ToUpper().EndsWith(".ASCX") || s.ToUpper().EndsWith(".ASHX") || s.ToUpper().EndsWith(".ASMX") || s.ToUpper().EndsWith(".ASP") || s.ToUpper().EndsWith(".ASPX") || s.ToUpper().EndsWith(".ASR") || s.ToUpper().EndsWith(".ATOM") || s.ToUpper().EndsWith(".ATT") || s.ToUpper().EndsWith(".AWM") || s.ToUpper().EndsWith(".AXD") || s.ToUpper().EndsWith(".BML") || s.ToUpper().EndsWith(".BOK") || s.ToUpper().EndsWith(".BR") || s.ToUpper().EndsWith(".BROWSER") || s.ToUpper().EndsWith(".BTAPP") || s.ToUpper().EndsWith(".BWP") || s.ToUpper().EndsWith(".CCBJS") || s.ToUpper().EndsWith(".CDF") || s.ToUpper().EndsWith(".CER") || s.ToUpper().EndsWith(".CFM") || s.ToUpper().EndsWith(".CFML") || s.ToUpper().EndsWith(".CHA") || s.ToUpper().EndsWith(".CHAT") || s.ToUpper().EndsWith(".CHM") || s.ToUpper().EndsWith(".CMS") || s.ToUpper().EndsWith(".CODASITE") || s.ToUpper().EndsWith(".COMPRESSED") || s.ToUpper().EndsWith(".CON") || s.ToUpper().EndsWith(".CPG") || s.ToUpper().EndsWith(".CPHD") || s.ToUpper().EndsWith(".CRL") || s.ToUpper().EndsWith(".CRT") || s.ToUpper().EndsWith(".CSHTML") || s.ToUpper().EndsWith(".CSP") || s.ToUpper().EndsWith(".CSR") || s.ToUpper().EndsWith(".CSS") || s.ToUpper().EndsWith(".DAP") || s.ToUpper().EndsWith(".DBM") || s.ToUpper().EndsWith(".DCR") || s.ToUpper().EndsWith(".DER") || s.ToUpper().EndsWith(".DHTML") || s.ToUpper().EndsWith(".DISCO") || s.ToUpper().EndsWith(".DISCOMAP") || s.ToUpper().EndsWith(".DLL") || s.ToUpper().EndsWith(".DML") || s.ToUpper().EndsWith(".DO") || s.ToUpper().EndsWith(".DOCHTML") || s.ToUpper().EndsWith(".DOCMHTML") || s.ToUpper().EndsWith(".DOTHTML") || s.ToUpper().EndsWith(".DOWNLOAD") || s.ToUpper().EndsWith(".DWT") || s.ToUpper().EndsWith(".ECE") || s.ToUpper().EndsWith(".EDGE") || s.ToUpper().EndsWith(".EPIBRW") || s.ToUpper().EndsWith(".ESPROJ") || s.ToUpper().EndsWith(".EWP") || s.ToUpper().EndsWith(".FCGI") || s.ToUpper().EndsWith(".FMP") || s.ToUpper().EndsWith(".FREEWAY") || s.ToUpper().EndsWith(".FWP") || s.ToUpper().EndsWith(".FWTB") || s.ToUpper().EndsWith(".FWTEMPLATE") || s.ToUpper().EndsWith(".FWTEMPLATEB") || s.ToUpper().EndsWith(".GNE") || s.ToUpper().EndsWith(".GSP") || s.ToUpper().EndsWith(".GSP") || s.ToUpper().EndsWith(".HAR") || s.ToUpper().EndsWith(".HDM") || s.ToUpper().EndsWith(".HDML") || s.ToUpper().EndsWith(".HTACCESS") || s.ToUpper().EndsWith(".HTC") || s.ToUpper().EndsWith(".HTM") || s.ToUpper().EndsWith(".HTML") || s.ToUpper().EndsWith(".HTX") || s.ToUpper().EndsWith(".HXS") || s.ToUpper().EndsWith(".HYPE") || s.ToUpper().EndsWith(".HYPERESOURCES") || s.ToUpper().EndsWith(".HYPESYMBOL") || s.ToUpper().EndsWith(".HYPETEMPLATE") || s.ToUpper().EndsWith(".IDC") || s.ToUpper().EndsWith(".IQY") || s.ToUpper().EndsWith(".ITMS") || s.ToUpper().EndsWith(".ITPC") || s.ToUpper().EndsWith(".IWDGT") || s.ToUpper().EndsWith(".JCZ") || s.ToUpper().EndsWith(".JHTML") || s.ToUpper().EndsWith(".JNLP") || s.ToUpper().EndsWith(".JS") || s.ToUpper().EndsWith(".JSON") || s.ToUpper().EndsWith(".JSP") || s.ToUpper().EndsWith(".JSPA") || s.ToUpper().EndsWith(".JSPX") || s.ToUpper().EndsWith(".JSS") || s.ToUpper().EndsWith(".JST") || s.ToUpper().EndsWith(".JVS") || s.ToUpper().EndsWith(".JWS") || s.ToUpper().EndsWith(".KIT") || s.ToUpper().EndsWith(".LASSO") || s.ToUpper().EndsWith(".LBC") || s.ToUpper().EndsWith(".LESS") || s.ToUpper().EndsWith(".MAFF") || s.ToUpper().EndsWith(".MAP") || s.ToUpper().EndsWith(".MAPX") || s.ToUpper().EndsWith(".MASTER") || s.ToUpper().EndsWith(".MHT") || s.ToUpper().EndsWith(".MHTML") || s.ToUpper().EndsWith(".MJS") || s.ToUpper().EndsWith(".MOZ") || s.ToUpper().EndsWith(".MSPX") || s.ToUpper().EndsWith(".MUSE") || s.ToUpper().EndsWith(".MVC") || s.ToUpper().EndsWith(".MVR") || s.ToUpper().EndsWith(".NOD") || s.ToUpper().EndsWith(".NXG") || s.ToUpper().EndsWith(".NZB") || s.ToUpper().EndsWith(".OAM") || s.ToUpper().EndsWith(".OBML") || s.ToUpper().EndsWith(".OBML15") || s.ToUpper().EndsWith(".OBML16") || s.ToUpper().EndsWith(".OGNC") || s.ToUpper().EndsWith(".OLP") || s.ToUpper().EndsWith(".OPML") || s.ToUpper().EndsWith(".OTH") || s.ToUpper().EndsWith(".P12") || s.ToUpper().EndsWith(".P7") || s.ToUpper().EndsWith(".P7B") || s.ToUpper().EndsWith(".P7C") || s.ToUpper().EndsWith(".PAC") || s.ToUpper().EndsWith(".PAGE") || s.ToUpper().EndsWith(".PEM") || s.ToUpper().EndsWith(".PHP") || s.ToUpper().EndsWith(".PHP2") || s.ToUpper().EndsWith(".PHP3") || s.ToUpper().EndsWith(".PHP4") || s.ToUpper().EndsWith(".PHP5") || s.ToUpper().EndsWith(".PHTM") || s.ToUpper().EndsWith(".PHTML") || s.ToUpper().EndsWith(".PPTHTML") || s.ToUpper().EndsWith(".PPTMHTML") || s.ToUpper().EndsWith(".PRF") || s.ToUpper().EndsWith(".PRO") || s.ToUpper().EndsWith(".PSP") || s.ToUpper().EndsWith(".PTW") || s.ToUpper().EndsWith(".PUB") || s.ToUpper().EndsWith(".QBO") || s.ToUpper().EndsWith(".QBX") || s.ToUpper().EndsWith(".QF") || s.ToUpper().EndsWith(".QRM") || s.ToUpper().EndsWith(".RFLW") || s.ToUpper().EndsWith(".RHTML") || s.ToUpper().EndsWith(".RJS") || s.ToUpper().EndsWith(".RSS") || s.ToUpper().EndsWith(".RT") || s.ToUpper().EndsWith(".RW3") || s.ToUpper().EndsWith(".RWP") || s.ToUpper().EndsWith(".RWSW") || s.ToUpper().EndsWith(".RWTHEME") || s.ToUpper().EndsWith(".SASS") || s.ToUpper().EndsWith(".SAVEDDECK") || s.ToUpper().EndsWith(".SCSS") || s.ToUpper().EndsWith(".SDB") || s.ToUpper().EndsWith(".SEAM") || s.ToUpper().EndsWith(".SHT") || s.ToUpper().EndsWith(".SHTM") || s.ToUpper().EndsWith(".SHTML") || s.ToUpper().EndsWith(".SITE") || s.ToUpper().EndsWith(".SITEMAP") || s.ToUpper().EndsWith(".SITES") || s.ToUpper().EndsWith(".SITES2") || s.ToUpper().EndsWith(".SPARKLE") || s.ToUpper().EndsWith(".SPC") || s.ToUpper().EndsWith(".SRF") || s.ToUpper().EndsWith(".SSP") || s.ToUpper().EndsWith(".STC") || s.ToUpper().EndsWith(".STL") || s.ToUpper().EndsWith(".STM") || s.ToUpper().EndsWith(".STML") || s.ToUpper().EndsWith(".STP") || s.ToUpper().EndsWith(".STRM") || s.ToUpper().EndsWith(".SUCK") || s.ToUpper().EndsWith(".SVC") || s.ToUpper().EndsWith(".SVR") || s.ToUpper().EndsWith(".SWZ") || s.ToUpper().EndsWith(".TPL") || s.ToUpper().EndsWith(".TVPI") || s.ToUpper().EndsWith(".TVVI") || s.ToUpper().EndsWith(".UCF") || s.ToUpper().EndsWith(".UHTML") || s.ToUpper().EndsWith(".URL") || s.ToUpper().EndsWith(".VBD") || s.ToUpper().EndsWith(".VBHTML") || s.ToUpper().EndsWith(".VDW") || s.ToUpper().EndsWith(".VLP") || s.ToUpper().EndsWith(".VRML") || s.ToUpper().EndsWith(".VRT") || s.ToUpper().EndsWith(".VSDISCO") || s.ToUpper().EndsWith(".WBS") || s.ToUpper().EndsWith(".WBXML") || s.ToUpper().EndsWith(".WDGT") || s.ToUpper().EndsWith(".WEB") || s.ToUpper().EndsWith(".WEBARCHIVE") || s.ToUpper().EndsWith(".WEBARCHIVEXML") || s.ToUpper().EndsWith(".WEBBOOKMARK") || s.ToUpper().EndsWith(".WEBHISTORY") || s.ToUpper().EndsWith(".WEBLOC") || s.ToUpper().EndsWith(".WEBSITE") || s.ToUpper().EndsWith(".WGP") || s.ToUpper().EndsWith(".WGT") || s.ToUpper().EndsWith(".WHTT") || s.ToUpper().EndsWith(".WIDGET") || s.ToUpper().EndsWith(".WML") || s.ToUpper().EndsWith(".WN") || s.ToUpper().EndsWith(".WOA") || s.ToUpper().EndsWith(".WPP") || s.ToUpper().EndsWith(".WPX") || s.ToUpper().EndsWith(".WRF") || s.ToUpper().EndsWith(".WSDL") || s.ToUpper().EndsWith(".XBEL") || s.ToUpper().EndsWith(".XBL") || s.ToUpper().EndsWith(".XFDL") || s.ToUpper().EndsWith(".XHT") || s.ToUpper().EndsWith(".XHTM") || s.ToUpper().EndsWith(".XHTML") || s.ToUpper().EndsWith(".XPD") || s.ToUpper().EndsWith(".XSS") || s.ToUpper().EndsWith(".XUL") || s.ToUpper().EndsWith(".XWS") || s.ToUpper().EndsWith(".ZFO") || s.ToUpper().EndsWith(".ZHTML") || s.ToUpper().EndsWith(".ZHTML") || s.ToUpper().EndsWith(".ZUL") || s.ToUpper().EndsWith(".ZVZ") );
                List<string> webFiles = e.ToList<string>();

                

                foreach (string webFile in webFiles)
                {
                    Console.WriteLine("Web file: " + webFile);
                    // DEBUG
                    


                    // At this point we need to determine what the website is for the shares
                    // Lets try to determine the IP of the machine that has the share hosted on.
                    // Then we can do some directory checking against different types of webservers 

                    // IIS
                    if (webFile.Contains("inetpub") && webFile.Contains("www"))
                    {
                        DirectoryInfo currentDirectoryInfo = new DirectoryInfo(webFile);
                        
                        // lets walk up the file path to identify where the root of the IIS server is located
                        for(DirectoryInfo nodeInfo = currentDirectoryInfo; nodeInfo.Parent != null; nodeInfo = nodeInfo.Parent)
                        {
                            try
                            {
                                
                                String grandParentNode = nodeInfo.Parent.Parent.Name;
                                String parentNode = nodeInfo.Parent.Name;
                                if (grandParentNode == "inetpub" && parentNode == "www")
                                {

                                    int parentIndex = webFile.IndexOf("www");


                                    // TODO: determine ip of the IIS server
                                    //      - maybe if webFile = "\\\\BobsComputer\\inetpub\\www\\hello.html" I can just transform it into "http://BobsComputer/hello.html"
                                    // DEBUG
                                    //string webFile2 = "\\\\192.168.0.32\\inetpub\\www\\hello.html";

                                    if (webFile[0] == '\\' && webFile[1] == '\\')
                                    {
                                        // get the ComputerName (BobsComputer)
                                        string sub = webFile.Substring(2, webFile.Length - 2);
                                        string computerName = sub.Substring(0, sub.IndexOf("\\"));
                                        
                                        string potentialURL = computerName + "/" + webFile.Substring(parentIndex + 4, webFile.Length - parentIndex - 4).Replace("\\", "/");

                                        //Console.WriteLine("Potential URL: " + potentialURL);

                                        // DEBUG
                                        //potentialURL = "stackoverflow.com/questions/";
                                        // DEBUG

                                        // Now lets check if that URL is actually valid
                                        if (isURLExist("http://" + potentialURL))
                                        {
                                            validURLs.Add(potentialURL);
                                            //Console.WriteLine("Valid URL: " + potentialURL);
                                        }
                                    } else
                                    {
                                        // well if the path doesn't start with \\BobsComputer\....\inetpub\www\...
                                        // then this is unexpected behavior as far as i know
                                        Console.WriteLine("Problemo: are we sure this is a share? ");
                                    }


                                    
                                    
                                }
                            } catch (Exception ee)
                            {
                                continue;
                            }
                            

                        }
                        
                    }
                    

                }


            }

            foreach (string validURL in validURLs) {
                Console.WriteLine("Valid URL: " + validURL);
            }
        }

        // Attempt to resolve the share path to a URL based on web.config
        public static void resolve()
        {

        }

        static void Main(string[] args)
        {
            var computers = GetComputers();
            if (args.Contains("ips"))
            {
                GetComputerAddresses(computers);
            }
            else if (args.Contains("shares"))
            {
                GetShares(computers);

                if(writablePaths.Count > 0)
                {
                    findLiveWebFiles();
                }

            }
            else
            {
                Console.WriteLine("Error: Not enough arguments. Please pass \"ip\" or \"shares\".");
            }



            findLiveWebFiles();
            Console.WriteLine("Done");
            Console.ReadLine();
        }
    }
}
