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
using System.Xml;

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
        static List<string> readableShares = new List<string>();
        static List<string> writableShares = new List<string>();
        static List<string> unreadableShares = new List<string>();
        static List<string> readableNotWritableShares = new List<string>();

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

                            
                            readableShares.Add("\\\\" + computer + "\\" + share.shi1_netname);

                            //Console.WriteLine("READABLE SHARE: " + share + "           " + share.shi1_netname);


                            try
                            {
                                // check if path is writable
                                // Attempt to get a list of security permissions from the folder. 
                                // This will raise an exception if the path is read only or do not have access to view the permissions. 
                                System.Security.AccessControl.DirectorySecurity ds = Directory.GetAccessControl(path);
                                writableShares.Add("\\\\" + computer + "\\" + share.shi1_netname);
                                writablePaths.Add("\\\\" + computer + "\\" + share.shi1_netname);
                                /*if (DirectoryHasPermission(path, FileSystemRights.Write)) { // alternative method of determining write access
                                    writableShares.Add(share.shi1_netname);
                                }*/

                            }
                            catch (Exception e)
                            {
                                readableNotWritableShares.Add("\\\\" + computer + "\\" + share.shi1_netname);
                            }
                            
                            
                        }
                        catch
                        {
                            if (!errors.Contains(share.shi1_netname))
                            {
                                unreadableShares.Add("\\\\" + computer + "\\" + share.shi1_netname);
                            }
                        }
                    }
                    if (unreadableShares.Count > 0 || readableShares.Count > 0 || writableShares.Count > 0) 
                    {
                        Console.WriteLine("\n\nShares for {0}:", computer);
                        if (unreadableShares.Count > 0)
                        {
                            Console.WriteLine("\n[--- Unreadable Shares ---]");
                            foreach (string share in unreadableShares)
                            {
                                Console.WriteLine("\t{0}", share);
                            }
                        }
                        if (readableShares.Count > 0)
                        {
                            Console.WriteLine("\n[--- Listable Shares ---]");
                            foreach (string share in readableShares)
                            {
                                Console.WriteLine("\t{0}", share);
                            }
                        }
                        if (writableShares.Count > 0)
                        {
                            Console.WriteLine("\n[--- Writable Shares ---]");
                            foreach (string share in writableShares)
                            {
                                Console.WriteLine("\t{0}", share);
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
            //writablePaths.Add("C:\\Users\\Karp\\Downloads");
            //readableShares.Add("C:\\Users\\Karp\\Downloads");
            List<string> validURLs = new List<string>();
            List<string> potentialURLs = new List<string>();
            string webConfig = "";

            // First lets get the web.config file(s)
            foreach(string path in readableShares)
            {
                try
                {
                    IEnumerable<string> webConfigEntries = Directory.GetFiles(path, "web.config", SearchOption.AllDirectories);
                    List<string> webConfigs = webConfigEntries.ToList<string>();

                    // BUG: for some reason this isn't finding web.config when I pass it C:\
                    //List<string> allFiles = GetAllAccessibleFiles(path, null);
                    //List<string> webConfigs = new List<string>();

                    /*foreach(string file in allFiles)
                    {
                        if (file.EndsWith("web.config"))
                        {
                            webConfigs.Add(file);
                        }
                    }*/

                    if (webConfigs.Count == 1)
                    {
                        // DEBUG BEHAVIOR
                        webConfig = webConfigs[0];
                    }
                    else if (webConfigs.Count == 2)
                    {
                        Console.WriteLine("DEBUG BEHAVIOR: more than one web.config file!");
                    }
                }
                catch (Exception) { continue; }
                

            }


            //       physicalPath,virtPath
            Dictionary<string, string> applicationPaths = new Dictionary<string, string>();
            List<string> goodBindings = new List<string>();
            List<string> webFiles = new List<string>();

            if (webConfig == "")
            {
                Console.WriteLine("\nNo web.config file found. Hunting for IIS anyway...");
            } else
            {
                // Now lets parse out the fields:
                // - physicalPath is the IIS root e.g.   C:\inetpub\wwwroot
                // - bindingInformation is value like    192.168.0.1:80:www.contoso.com
                XmlDocument xmlDoc = new XmlDocument(); // Create an XML document object
                xmlDoc.Load(webConfig); // Load the XML document from the specified file

                


                // Get elements;
                XmlNodeList sitesXML = xmlDoc.SelectNodes("//site");
                List<string> websites = new List<string>();

                try
                {
                    foreach (XmlNode site in sitesXML)
                    {
                        
                        List<string> bindings = new List<string>();

                        //List<string> virtDirectoryStrings = new List<string>();
                        XmlNodeList applications = site.SelectNodes("//application");

                        foreach (XmlNode application in applications)
                        {
                            XmlNodeList virtDirectories = application.SelectNodes("virtualDirectory");
                            foreach (XmlNode virtDirectory in virtDirectories)
                            {
                                try
                                {
                                    string path = virtDirectory.Attributes["path"].Value;
                                    string physicalPath = virtDirectory.Attributes["physicalPath"].Value;
                                    applicationPaths.Add(physicalPath, path);
                                }
                                catch (Exception)
                                {
                                    // do nothing
                                }
                                

                            }

                        }

                        XmlNodeList bindingsXmlList = site.SelectNodes("//bindings");
                        foreach (XmlNode binding in bindingsXmlList)
                        {
                            foreach(XmlNode bindingAgain in binding.ChildNodes)
                            {
                                try
                                {
                                    // First lets assume that the protocol is http for now. This can be confirmed by checking the binding 'protocol' attribute
                                    string bindingInformation = bindingAgain.Attributes["bindingInformation"].Value;
                                    bindings.Add(bindingInformation);
                                }
                                catch (Exception)
                                {
                                    // do nothing
                                }
                            }
                            
                            

                        }

                        // create into potential site and add it to websites List
                        Console.WriteLine("applicationPaths count: " + applicationPaths.Count);
                        Console.WriteLine("bindings count: " + bindings.Count);
                        foreach(string binding in bindings)
                        {
                            Console.WriteLine("\tbinding: " + binding);
                        }


                        // convert bindings into actual IPs/URLs
                        foreach(string binding in bindings)
                        {
                            try
                            {
                                string[] split = binding.Split(':');
                                goodBindings.Add(split[0]);
                                goodBindings.Add(split[2]);
                                Console.WriteLine("Bindings are good.");
                            }
                            catch (Exception) { Console.WriteLine("Problem converting *:*:* bindingInformation web.config property into ip/url"); }
                            

                        }
                        
                    }
                } catch (Exception)
                {
                    Console.WriteLine("Problem parsing web.config");
                }


                // populate the webFiles immediately since we know the iisRoot
                /*foreach (KeyValuePair<string, string> iisRoot in applicationPaths)
                {
                    IEnumerable<string> e = Directory.GetFiles(iisRoot.Key, "*.*", SearchOption.AllDirectories).Where(s => s.ToUpper().EndsWith(".A4P") || s.ToUpper().EndsWith(".A5W") || s.ToUpper().EndsWith(".ADR") || s.ToUpper().EndsWith(".AEX") || s.ToUpper().EndsWith(".ALX") || s.ToUpper().EndsWith(".AN") || s.ToUpper().EndsWith(".AP") || s.ToUpper().EndsWith(".APPCACHE") || s.ToUpper().EndsWith(".ARO") || s.ToUpper().EndsWith(".ASA") || s.ToUpper().EndsWith(".ASAX") || s.ToUpper().EndsWith(".ASCX") || s.ToUpper().EndsWith(".ASHX") || s.ToUpper().EndsWith(".ASMX") || s.ToUpper().EndsWith(".ASP") || s.ToUpper().EndsWith(".ASPX") || s.ToUpper().EndsWith(".ASR") || s.ToUpper().EndsWith(".ATOM") || s.ToUpper().EndsWith(".ATT") || s.ToUpper().EndsWith(".AWM") || s.ToUpper().EndsWith(".AXD") || s.ToUpper().EndsWith(".BML") || s.ToUpper().EndsWith(".BOK") || s.ToUpper().EndsWith(".BR") || s.ToUpper().EndsWith(".BROWSER") || s.ToUpper().EndsWith(".BTAPP") || s.ToUpper().EndsWith(".BWP") || s.ToUpper().EndsWith(".CCBJS") || s.ToUpper().EndsWith(".CDF") || s.ToUpper().EndsWith(".CER") || s.ToUpper().EndsWith(".CFM") || s.ToUpper().EndsWith(".CFML") || s.ToUpper().EndsWith(".CHA") || s.ToUpper().EndsWith(".CHAT") || s.ToUpper().EndsWith(".CHM") || s.ToUpper().EndsWith(".CMS") || s.ToUpper().EndsWith(".CODASITE") || s.ToUpper().EndsWith(".COMPRESSED") || s.ToUpper().EndsWith(".CON") || s.ToUpper().EndsWith(".CPG") || s.ToUpper().EndsWith(".CPHD") || s.ToUpper().EndsWith(".CRL") || s.ToUpper().EndsWith(".CRT") || s.ToUpper().EndsWith(".CSHTML") || s.ToUpper().EndsWith(".CSP") || s.ToUpper().EndsWith(".CSR") || s.ToUpper().EndsWith(".CSS") || s.ToUpper().EndsWith(".DAP") || s.ToUpper().EndsWith(".DBM") || s.ToUpper().EndsWith(".DCR") || s.ToUpper().EndsWith(".DER") || s.ToUpper().EndsWith(".DHTML") || s.ToUpper().EndsWith(".DISCO") || s.ToUpper().EndsWith(".DISCOMAP") || s.ToUpper().EndsWith(".DML") || s.ToUpper().EndsWith(".DO") || s.ToUpper().EndsWith(".DOCHTML") || s.ToUpper().EndsWith(".DOCMHTML") || s.ToUpper().EndsWith(".DOTHTML") || s.ToUpper().EndsWith(".DOWNLOAD") || s.ToUpper().EndsWith(".DWT") || s.ToUpper().EndsWith(".ECE") || s.ToUpper().EndsWith(".EDGE") || s.ToUpper().EndsWith(".EPIBRW") || s.ToUpper().EndsWith(".ESPROJ") || s.ToUpper().EndsWith(".EWP") || s.ToUpper().EndsWith(".FCGI") || s.ToUpper().EndsWith(".FMP") || s.ToUpper().EndsWith(".FREEWAY") || s.ToUpper().EndsWith(".FWP") || s.ToUpper().EndsWith(".FWTB") || s.ToUpper().EndsWith(".FWTEMPLATE") || s.ToUpper().EndsWith(".FWTEMPLATEB") || s.ToUpper().EndsWith(".GNE") || s.ToUpper().EndsWith(".GSP") || s.ToUpper().EndsWith(".GSP") || s.ToUpper().EndsWith(".HAR") || s.ToUpper().EndsWith(".HDM") || s.ToUpper().EndsWith(".HDML") || s.ToUpper().EndsWith(".HTACCESS") || s.ToUpper().EndsWith(".HTC") || s.ToUpper().EndsWith(".HTM") || s.ToUpper().EndsWith(".HTML") || s.ToUpper().EndsWith(".HTX") || s.ToUpper().EndsWith(".HXS") || s.ToUpper().EndsWith(".HYPE") || s.ToUpper().EndsWith(".HYPERESOURCES") || s.ToUpper().EndsWith(".HYPESYMBOL") || s.ToUpper().EndsWith(".HYPETEMPLATE") || s.ToUpper().EndsWith(".IDC") || s.ToUpper().EndsWith(".IQY") || s.ToUpper().EndsWith(".ITMS") || s.ToUpper().EndsWith(".ITPC") || s.ToUpper().EndsWith(".IWDGT") || s.ToUpper().EndsWith(".JCZ") || s.ToUpper().EndsWith(".JHTML") || s.ToUpper().EndsWith(".JNLP") || s.ToUpper().EndsWith(".JS") || s.ToUpper().EndsWith(".JSON") || s.ToUpper().EndsWith(".JSP") || s.ToUpper().EndsWith(".JSPA") || s.ToUpper().EndsWith(".JSPX") || s.ToUpper().EndsWith(".JSS") || s.ToUpper().EndsWith(".JST") || s.ToUpper().EndsWith(".JVS") || s.ToUpper().EndsWith(".JWS") || s.ToUpper().EndsWith(".KIT") || s.ToUpper().EndsWith(".LASSO") || s.ToUpper().EndsWith(".LBC") || s.ToUpper().EndsWith(".LESS") || s.ToUpper().EndsWith(".MAFF") || s.ToUpper().EndsWith(".MAP") || s.ToUpper().EndsWith(".MAPX") || s.ToUpper().EndsWith(".MASTER") || s.ToUpper().EndsWith(".MHT") || s.ToUpper().EndsWith(".MHTML") || s.ToUpper().EndsWith(".MJS") || s.ToUpper().EndsWith(".MOZ") || s.ToUpper().EndsWith(".MSPX") || s.ToUpper().EndsWith(".MUSE") || s.ToUpper().EndsWith(".MVC") || s.ToUpper().EndsWith(".MVR") || s.ToUpper().EndsWith(".NOD") || s.ToUpper().EndsWith(".NXG") || s.ToUpper().EndsWith(".NZB") || s.ToUpper().EndsWith(".OAM") || s.ToUpper().EndsWith(".OBML") || s.ToUpper().EndsWith(".OBML15") || s.ToUpper().EndsWith(".OBML16") || s.ToUpper().EndsWith(".OGNC") || s.ToUpper().EndsWith(".OLP") || s.ToUpper().EndsWith(".OPML") || s.ToUpper().EndsWith(".OTH") || s.ToUpper().EndsWith(".P12") || s.ToUpper().EndsWith(".P7") || s.ToUpper().EndsWith(".P7B") || s.ToUpper().EndsWith(".P7C") || s.ToUpper().EndsWith(".PAC") || s.ToUpper().EndsWith(".PAGE") || s.ToUpper().EndsWith(".PEM") || s.ToUpper().EndsWith(".PHP") || s.ToUpper().EndsWith(".PHP2") || s.ToUpper().EndsWith(".PHP3") || s.ToUpper().EndsWith(".PHP4") || s.ToUpper().EndsWith(".PHP5") || s.ToUpper().EndsWith(".PHTM") || s.ToUpper().EndsWith(".PHTML") || s.ToUpper().EndsWith(".PPTHTML") || s.ToUpper().EndsWith(".PPTMHTML") || s.ToUpper().EndsWith(".PRF") || s.ToUpper().EndsWith(".PRO") || s.ToUpper().EndsWith(".PSP") || s.ToUpper().EndsWith(".PTW") || s.ToUpper().EndsWith(".PUB") || s.ToUpper().EndsWith(".QBO") || s.ToUpper().EndsWith(".QBX") || s.ToUpper().EndsWith(".QF") || s.ToUpper().EndsWith(".QRM") || s.ToUpper().EndsWith(".RFLW") || s.ToUpper().EndsWith(".RHTML") || s.ToUpper().EndsWith(".RJS") || s.ToUpper().EndsWith(".RSS") || s.ToUpper().EndsWith(".RT") || s.ToUpper().EndsWith(".RW3") || s.ToUpper().EndsWith(".RWP") || s.ToUpper().EndsWith(".RWSW") || s.ToUpper().EndsWith(".RWTHEME") || s.ToUpper().EndsWith(".SASS") || s.ToUpper().EndsWith(".SAVEDDECK") || s.ToUpper().EndsWith(".SCSS") || s.ToUpper().EndsWith(".SDB") || s.ToUpper().EndsWith(".SEAM") || s.ToUpper().EndsWith(".SHT") || s.ToUpper().EndsWith(".SHTM") || s.ToUpper().EndsWith(".SHTML") || s.ToUpper().EndsWith(".SITE") || s.ToUpper().EndsWith(".SITEMAP") || s.ToUpper().EndsWith(".SITES") || s.ToUpper().EndsWith(".SITES2") || s.ToUpper().EndsWith(".SPARKLE") || s.ToUpper().EndsWith(".SPC") || s.ToUpper().EndsWith(".SRF") || s.ToUpper().EndsWith(".SSP") || s.ToUpper().EndsWith(".STC") || s.ToUpper().EndsWith(".STL") || s.ToUpper().EndsWith(".STM") || s.ToUpper().EndsWith(".STML") || s.ToUpper().EndsWith(".STP") || s.ToUpper().EndsWith(".STRM") || s.ToUpper().EndsWith(".SUCK") || s.ToUpper().EndsWith(".SVC") || s.ToUpper().EndsWith(".SVR") || s.ToUpper().EndsWith(".SWZ") || s.ToUpper().EndsWith(".TPL") || s.ToUpper().EndsWith(".TVPI") || s.ToUpper().EndsWith(".TVVI") || s.ToUpper().EndsWith(".UCF") || s.ToUpper().EndsWith(".UHTML") || s.ToUpper().EndsWith(".URL") || s.ToUpper().EndsWith(".VBD") || s.ToUpper().EndsWith(".VBHTML") || s.ToUpper().EndsWith(".VDW") || s.ToUpper().EndsWith(".VLP") || s.ToUpper().EndsWith(".VRML") || s.ToUpper().EndsWith(".VRT") || s.ToUpper().EndsWith(".VSDISCO") || s.ToUpper().EndsWith(".WBS") || s.ToUpper().EndsWith(".WBXML") || s.ToUpper().EndsWith(".WDGT") || s.ToUpper().EndsWith(".WEB") || s.ToUpper().EndsWith(".WEBARCHIVE") || s.ToUpper().EndsWith(".WEBARCHIVEXML") || s.ToUpper().EndsWith(".WEBBOOKMARK") || s.ToUpper().EndsWith(".WEBHISTORY") || s.ToUpper().EndsWith(".WEBLOC") || s.ToUpper().EndsWith(".WEBSITE") || s.ToUpper().EndsWith(".WGP") || s.ToUpper().EndsWith(".WGT") || s.ToUpper().EndsWith(".WHTT") || s.ToUpper().EndsWith(".WIDGET") || s.ToUpper().EndsWith(".WML") || s.ToUpper().EndsWith(".WN") || s.ToUpper().EndsWith(".WOA") || s.ToUpper().EndsWith(".WPP") || s.ToUpper().EndsWith(".WPX") || s.ToUpper().EndsWith(".WRF") || s.ToUpper().EndsWith(".WSDL") || s.ToUpper().EndsWith(".XBEL") || s.ToUpper().EndsWith(".XBL") || s.ToUpper().EndsWith(".XFDL") || s.ToUpper().EndsWith(".XHT") || s.ToUpper().EndsWith(".XHTM") || s.ToUpper().EndsWith(".XHTML") || s.ToUpper().EndsWith(".XPD") || s.ToUpper().EndsWith(".XSS") || s.ToUpper().EndsWith(".XUL") || s.ToUpper().EndsWith(".XWS") || s.ToUpper().EndsWith(".ZFO") || s.ToUpper().EndsWith(".ZHTML") || s.ToUpper().EndsWith(".ZHTML") || s.ToUpper().EndsWith(".ZUL") || s.ToUpper().EndsWith(".ZVZ"));
                    List<string> somewebFiles = e.ToList<string>();
                    webFiles.Concat(somewebFiles);
                }*/

                //  populate the webFiles immediately since we know the iisRoot
                // NOTE: we actually don't. we are assuming that the web.config is within the root
                IEnumerable<string> e = Directory.GetFiles(webConfig.Substring(0,webConfig.LastIndexOf("\\")), "*.*", SearchOption.AllDirectories).Where(s => s.ToUpper().EndsWith(".A4P") || s.ToUpper().EndsWith(".A5W") || s.ToUpper().EndsWith(".ADR") || s.ToUpper().EndsWith(".AEX") || s.ToUpper().EndsWith(".ALX") || s.ToUpper().EndsWith(".AN") || s.ToUpper().EndsWith(".AP") || s.ToUpper().EndsWith(".APPCACHE") || s.ToUpper().EndsWith(".ARO") || s.ToUpper().EndsWith(".ASA") || s.ToUpper().EndsWith(".ASAX") || s.ToUpper().EndsWith(".ASCX") || s.ToUpper().EndsWith(".ASHX") || s.ToUpper().EndsWith(".ASMX") || s.ToUpper().EndsWith(".ASP") || s.ToUpper().EndsWith(".ASPX") || s.ToUpper().EndsWith(".ASR") || s.ToUpper().EndsWith(".ATOM") || s.ToUpper().EndsWith(".ATT") || s.ToUpper().EndsWith(".AWM") || s.ToUpper().EndsWith(".AXD") || s.ToUpper().EndsWith(".BML") || s.ToUpper().EndsWith(".BOK") || s.ToUpper().EndsWith(".BR") || s.ToUpper().EndsWith(".BROWSER") || s.ToUpper().EndsWith(".BTAPP") || s.ToUpper().EndsWith(".BWP") || s.ToUpper().EndsWith(".CCBJS") || s.ToUpper().EndsWith(".CDF") || s.ToUpper().EndsWith(".CER") || s.ToUpper().EndsWith(".CFM") || s.ToUpper().EndsWith(".CFML") || s.ToUpper().EndsWith(".CHA") || s.ToUpper().EndsWith(".CHAT") || s.ToUpper().EndsWith(".CHM") || s.ToUpper().EndsWith(".CMS") || s.ToUpper().EndsWith(".CODASITE") || s.ToUpper().EndsWith(".COMPRESSED") || s.ToUpper().EndsWith(".CON") || s.ToUpper().EndsWith(".CPG") || s.ToUpper().EndsWith(".CPHD") || s.ToUpper().EndsWith(".CRL") || s.ToUpper().EndsWith(".CRT") || s.ToUpper().EndsWith(".CSHTML") || s.ToUpper().EndsWith(".CSP") || s.ToUpper().EndsWith(".CSR") || s.ToUpper().EndsWith(".CSS") || s.ToUpper().EndsWith(".DAP") || s.ToUpper().EndsWith(".DBM") || s.ToUpper().EndsWith(".DCR") || s.ToUpper().EndsWith(".DER") || s.ToUpper().EndsWith(".DHTML") || s.ToUpper().EndsWith(".DISCO") || s.ToUpper().EndsWith(".DISCOMAP") || s.ToUpper().EndsWith(".DML") || s.ToUpper().EndsWith(".DO") || s.ToUpper().EndsWith(".DOCHTML") || s.ToUpper().EndsWith(".DOCMHTML") || s.ToUpper().EndsWith(".DOTHTML") || s.ToUpper().EndsWith(".DOWNLOAD") || s.ToUpper().EndsWith(".DWT") || s.ToUpper().EndsWith(".ECE") || s.ToUpper().EndsWith(".EDGE") || s.ToUpper().EndsWith(".EPIBRW") || s.ToUpper().EndsWith(".ESPROJ") || s.ToUpper().EndsWith(".EWP") || s.ToUpper().EndsWith(".FCGI") || s.ToUpper().EndsWith(".FMP") || s.ToUpper().EndsWith(".FREEWAY") || s.ToUpper().EndsWith(".FWP") || s.ToUpper().EndsWith(".FWTB") || s.ToUpper().EndsWith(".FWTEMPLATE") || s.ToUpper().EndsWith(".FWTEMPLATEB") || s.ToUpper().EndsWith(".GNE") || s.ToUpper().EndsWith(".GSP") || s.ToUpper().EndsWith(".GSP") || s.ToUpper().EndsWith(".HAR") || s.ToUpper().EndsWith(".HDM") || s.ToUpper().EndsWith(".HDML") || s.ToUpper().EndsWith(".HTACCESS") || s.ToUpper().EndsWith(".HTC") || s.ToUpper().EndsWith(".HTM") || s.ToUpper().EndsWith(".HTML") || s.ToUpper().EndsWith(".HTX") || s.ToUpper().EndsWith(".HXS") || s.ToUpper().EndsWith(".HYPE") || s.ToUpper().EndsWith(".HYPERESOURCES") || s.ToUpper().EndsWith(".HYPESYMBOL") || s.ToUpper().EndsWith(".HYPETEMPLATE") || s.ToUpper().EndsWith(".IDC") || s.ToUpper().EndsWith(".IQY") || s.ToUpper().EndsWith(".ITMS") || s.ToUpper().EndsWith(".ITPC") || s.ToUpper().EndsWith(".IWDGT") || s.ToUpper().EndsWith(".JCZ") || s.ToUpper().EndsWith(".JHTML") || s.ToUpper().EndsWith(".JNLP") || s.ToUpper().EndsWith(".JS") || s.ToUpper().EndsWith(".JSON") || s.ToUpper().EndsWith(".JSP") || s.ToUpper().EndsWith(".JSPA") || s.ToUpper().EndsWith(".JSPX") || s.ToUpper().EndsWith(".JSS") || s.ToUpper().EndsWith(".JST") || s.ToUpper().EndsWith(".JVS") || s.ToUpper().EndsWith(".JWS") || s.ToUpper().EndsWith(".KIT") || s.ToUpper().EndsWith(".LASSO") || s.ToUpper().EndsWith(".LBC") || s.ToUpper().EndsWith(".LESS") || s.ToUpper().EndsWith(".MAFF") || s.ToUpper().EndsWith(".MAP") || s.ToUpper().EndsWith(".MAPX") || s.ToUpper().EndsWith(".MASTER") || s.ToUpper().EndsWith(".MHT") || s.ToUpper().EndsWith(".MHTML") || s.ToUpper().EndsWith(".MJS") || s.ToUpper().EndsWith(".MOZ") || s.ToUpper().EndsWith(".MSPX") || s.ToUpper().EndsWith(".MUSE") || s.ToUpper().EndsWith(".MVC") || s.ToUpper().EndsWith(".MVR") || s.ToUpper().EndsWith(".NOD") || s.ToUpper().EndsWith(".NXG") || s.ToUpper().EndsWith(".NZB") || s.ToUpper().EndsWith(".OAM") || s.ToUpper().EndsWith(".OBML") || s.ToUpper().EndsWith(".OBML15") || s.ToUpper().EndsWith(".OBML16") || s.ToUpper().EndsWith(".OGNC") || s.ToUpper().EndsWith(".OLP") || s.ToUpper().EndsWith(".OPML") || s.ToUpper().EndsWith(".OTH") || s.ToUpper().EndsWith(".P12") || s.ToUpper().EndsWith(".P7") || s.ToUpper().EndsWith(".P7B") || s.ToUpper().EndsWith(".P7C") || s.ToUpper().EndsWith(".PAC") || s.ToUpper().EndsWith(".PAGE") || s.ToUpper().EndsWith(".PEM") || s.ToUpper().EndsWith(".PHP") || s.ToUpper().EndsWith(".PHP2") || s.ToUpper().EndsWith(".PHP3") || s.ToUpper().EndsWith(".PHP4") || s.ToUpper().EndsWith(".PHP5") || s.ToUpper().EndsWith(".PHTM") || s.ToUpper().EndsWith(".PHTML") || s.ToUpper().EndsWith(".PPTHTML") || s.ToUpper().EndsWith(".PPTMHTML") || s.ToUpper().EndsWith(".PRF") || s.ToUpper().EndsWith(".PRO") || s.ToUpper().EndsWith(".PSP") || s.ToUpper().EndsWith(".PTW") || s.ToUpper().EndsWith(".PUB") || s.ToUpper().EndsWith(".QBO") || s.ToUpper().EndsWith(".QBX") || s.ToUpper().EndsWith(".QF") || s.ToUpper().EndsWith(".QRM") || s.ToUpper().EndsWith(".RFLW") || s.ToUpper().EndsWith(".RHTML") || s.ToUpper().EndsWith(".RJS") || s.ToUpper().EndsWith(".RSS") || s.ToUpper().EndsWith(".RT") || s.ToUpper().EndsWith(".RW3") || s.ToUpper().EndsWith(".RWP") || s.ToUpper().EndsWith(".RWSW") || s.ToUpper().EndsWith(".RWTHEME") || s.ToUpper().EndsWith(".SASS") || s.ToUpper().EndsWith(".SAVEDDECK") || s.ToUpper().EndsWith(".SCSS") || s.ToUpper().EndsWith(".SDB") || s.ToUpper().EndsWith(".SEAM") || s.ToUpper().EndsWith(".SHT") || s.ToUpper().EndsWith(".SHTM") || s.ToUpper().EndsWith(".SHTML") || s.ToUpper().EndsWith(".SITE") || s.ToUpper().EndsWith(".SITEMAP") || s.ToUpper().EndsWith(".SITES") || s.ToUpper().EndsWith(".SITES2") || s.ToUpper().EndsWith(".SPARKLE") || s.ToUpper().EndsWith(".SPC") || s.ToUpper().EndsWith(".SRF") || s.ToUpper().EndsWith(".SSP") || s.ToUpper().EndsWith(".STC") || s.ToUpper().EndsWith(".STL") || s.ToUpper().EndsWith(".STM") || s.ToUpper().EndsWith(".STML") || s.ToUpper().EndsWith(".STP") || s.ToUpper().EndsWith(".STRM") || s.ToUpper().EndsWith(".SUCK") || s.ToUpper().EndsWith(".SVC") || s.ToUpper().EndsWith(".SVR") || s.ToUpper().EndsWith(".SWZ") || s.ToUpper().EndsWith(".TPL") || s.ToUpper().EndsWith(".TVPI") || s.ToUpper().EndsWith(".TVVI") || s.ToUpper().EndsWith(".UCF") || s.ToUpper().EndsWith(".UHTML") || s.ToUpper().EndsWith(".URL") || s.ToUpper().EndsWith(".VBD") || s.ToUpper().EndsWith(".VBHTML") || s.ToUpper().EndsWith(".VDW") || s.ToUpper().EndsWith(".VLP") || s.ToUpper().EndsWith(".VRML") || s.ToUpper().EndsWith(".VRT") || s.ToUpper().EndsWith(".VSDISCO") || s.ToUpper().EndsWith(".WBS") || s.ToUpper().EndsWith(".WBXML") || s.ToUpper().EndsWith(".WDGT") || s.ToUpper().EndsWith(".WEB") || s.ToUpper().EndsWith(".WEBARCHIVE") || s.ToUpper().EndsWith(".WEBARCHIVEXML") || s.ToUpper().EndsWith(".WEBBOOKMARK") || s.ToUpper().EndsWith(".WEBHISTORY") || s.ToUpper().EndsWith(".WEBLOC") || s.ToUpper().EndsWith(".WEBSITE") || s.ToUpper().EndsWith(".WGP") || s.ToUpper().EndsWith(".WGT") || s.ToUpper().EndsWith(".WHTT") || s.ToUpper().EndsWith(".WIDGET") || s.ToUpper().EndsWith(".WML") || s.ToUpper().EndsWith(".WN") || s.ToUpper().EndsWith(".WOA") || s.ToUpper().EndsWith(".WPP") || s.ToUpper().EndsWith(".WPX") || s.ToUpper().EndsWith(".WRF") || s.ToUpper().EndsWith(".WSDL") || s.ToUpper().EndsWith(".XBEL") || s.ToUpper().EndsWith(".XBL") || s.ToUpper().EndsWith(".XFDL") || s.ToUpper().EndsWith(".XHT") || s.ToUpper().EndsWith(".XHTM") || s.ToUpper().EndsWith(".XHTML") || s.ToUpper().EndsWith(".XPD") || s.ToUpper().EndsWith(".XSS") || s.ToUpper().EndsWith(".XUL") || s.ToUpper().EndsWith(".XWS") || s.ToUpper().EndsWith(".ZFO") || s.ToUpper().EndsWith(".ZHTML") || s.ToUpper().EndsWith(".ZHTML") || s.ToUpper().EndsWith(".ZUL") || s.ToUpper().EndsWith(".ZVZ"));
                List<string> somewebFiles = e.ToList<string>();
                webFiles.Concat(somewebFiles);

                Console.WriteLine("Reading web.config root is good.");


            }

            // applicationPaths and goodBindings are now populated
            List<string> defaultIISPaths = new List<string>();

            foreach (string aPath in writablePaths)
            {


                // Check non case sensitive web file extensions
                // I used the ones from this website: https://fileinfo.com/filetypes/web

                // BUG: if you use this method of getting files on C:\ for instance, it'll throw an UnauthorizedException

                try {


                    

                    if(webFiles.Count == 0) // no web.config
                    {
                        // this might be causing permission issue if there's subfolders that throw UnauthorizedException
                        IEnumerable<string> e = Directory.GetFiles(aPath, "*.*", SearchOption.AllDirectories).Where(s => s.ToUpper().EndsWith(".A4P") || s.ToUpper().EndsWith(".A5W") || s.ToUpper().EndsWith(".ADR") || s.ToUpper().EndsWith(".AEX") || s.ToUpper().EndsWith(".ALX") || s.ToUpper().EndsWith(".AN") || s.ToUpper().EndsWith(".AP") || s.ToUpper().EndsWith(".APPCACHE") || s.ToUpper().EndsWith(".ARO") || s.ToUpper().EndsWith(".ASA") || s.ToUpper().EndsWith(".ASAX") || s.ToUpper().EndsWith(".ASCX") || s.ToUpper().EndsWith(".ASHX") || s.ToUpper().EndsWith(".ASMX") || s.ToUpper().EndsWith(".ASP") || s.ToUpper().EndsWith(".ASPX") || s.ToUpper().EndsWith(".ASR") || s.ToUpper().EndsWith(".ATOM") || s.ToUpper().EndsWith(".ATT") || s.ToUpper().EndsWith(".AWM") || s.ToUpper().EndsWith(".AXD") || s.ToUpper().EndsWith(".BML") || s.ToUpper().EndsWith(".BOK") || s.ToUpper().EndsWith(".BR") || s.ToUpper().EndsWith(".BROWSER") || s.ToUpper().EndsWith(".BTAPP") || s.ToUpper().EndsWith(".BWP") || s.ToUpper().EndsWith(".CCBJS") || s.ToUpper().EndsWith(".CDF") || s.ToUpper().EndsWith(".CER") || s.ToUpper().EndsWith(".CFM") || s.ToUpper().EndsWith(".CFML") || s.ToUpper().EndsWith(".CHA") || s.ToUpper().EndsWith(".CHAT") || s.ToUpper().EndsWith(".CHM") || s.ToUpper().EndsWith(".CMS") || s.ToUpper().EndsWith(".CODASITE") || s.ToUpper().EndsWith(".COMPRESSED") || s.ToUpper().EndsWith(".CON") || s.ToUpper().EndsWith(".CPG") || s.ToUpper().EndsWith(".CPHD") || s.ToUpper().EndsWith(".CRL") || s.ToUpper().EndsWith(".CRT") || s.ToUpper().EndsWith(".CSHTML") || s.ToUpper().EndsWith(".CSP") || s.ToUpper().EndsWith(".CSR") || s.ToUpper().EndsWith(".CSS") || s.ToUpper().EndsWith(".DAP") || s.ToUpper().EndsWith(".DBM") || s.ToUpper().EndsWith(".DCR") || s.ToUpper().EndsWith(".DER") || s.ToUpper().EndsWith(".DHTML") || s.ToUpper().EndsWith(".DISCO") || s.ToUpper().EndsWith(".DISCOMAP") || s.ToUpper().EndsWith(".DML") || s.ToUpper().EndsWith(".DO") || s.ToUpper().EndsWith(".DOCHTML") || s.ToUpper().EndsWith(".DOCMHTML") || s.ToUpper().EndsWith(".DOTHTML") || s.ToUpper().EndsWith(".DOWNLOAD") || s.ToUpper().EndsWith(".DWT") || s.ToUpper().EndsWith(".ECE") || s.ToUpper().EndsWith(".EDGE") || s.ToUpper().EndsWith(".EPIBRW") || s.ToUpper().EndsWith(".ESPROJ") || s.ToUpper().EndsWith(".EWP") || s.ToUpper().EndsWith(".FCGI") || s.ToUpper().EndsWith(".FMP") || s.ToUpper().EndsWith(".FREEWAY") || s.ToUpper().EndsWith(".FWP") || s.ToUpper().EndsWith(".FWTB") || s.ToUpper().EndsWith(".FWTEMPLATE") || s.ToUpper().EndsWith(".FWTEMPLATEB") || s.ToUpper().EndsWith(".GNE") || s.ToUpper().EndsWith(".GSP") || s.ToUpper().EndsWith(".GSP") || s.ToUpper().EndsWith(".HAR") || s.ToUpper().EndsWith(".HDM") || s.ToUpper().EndsWith(".HDML") || s.ToUpper().EndsWith(".HTACCESS") || s.ToUpper().EndsWith(".HTC") || s.ToUpper().EndsWith(".HTM") || s.ToUpper().EndsWith(".HTML") || s.ToUpper().EndsWith(".HTX") || s.ToUpper().EndsWith(".HXS") || s.ToUpper().EndsWith(".HYPE") || s.ToUpper().EndsWith(".HYPERESOURCES") || s.ToUpper().EndsWith(".HYPESYMBOL") || s.ToUpper().EndsWith(".HYPETEMPLATE") || s.ToUpper().EndsWith(".IDC") || s.ToUpper().EndsWith(".IQY") || s.ToUpper().EndsWith(".ITMS") || s.ToUpper().EndsWith(".ITPC") || s.ToUpper().EndsWith(".IWDGT") || s.ToUpper().EndsWith(".JCZ") || s.ToUpper().EndsWith(".JHTML") || s.ToUpper().EndsWith(".JNLP") || s.ToUpper().EndsWith(".JS") || s.ToUpper().EndsWith(".JSON") || s.ToUpper().EndsWith(".JSP") || s.ToUpper().EndsWith(".JSPA") || s.ToUpper().EndsWith(".JSPX") || s.ToUpper().EndsWith(".JSS") || s.ToUpper().EndsWith(".JST") || s.ToUpper().EndsWith(".JVS") || s.ToUpper().EndsWith(".JWS") || s.ToUpper().EndsWith(".KIT") || s.ToUpper().EndsWith(".LASSO") || s.ToUpper().EndsWith(".LBC") || s.ToUpper().EndsWith(".LESS") || s.ToUpper().EndsWith(".MAFF") || s.ToUpper().EndsWith(".MAP") || s.ToUpper().EndsWith(".MAPX") || s.ToUpper().EndsWith(".MASTER") || s.ToUpper().EndsWith(".MHT") || s.ToUpper().EndsWith(".MHTML") || s.ToUpper().EndsWith(".MJS") || s.ToUpper().EndsWith(".MOZ") || s.ToUpper().EndsWith(".MSPX") || s.ToUpper().EndsWith(".MUSE") || s.ToUpper().EndsWith(".MVC") || s.ToUpper().EndsWith(".MVR") || s.ToUpper().EndsWith(".NOD") || s.ToUpper().EndsWith(".NXG") || s.ToUpper().EndsWith(".NZB") || s.ToUpper().EndsWith(".OAM") || s.ToUpper().EndsWith(".OBML") || s.ToUpper().EndsWith(".OBML15") || s.ToUpper().EndsWith(".OBML16") || s.ToUpper().EndsWith(".OGNC") || s.ToUpper().EndsWith(".OLP") || s.ToUpper().EndsWith(".OPML") || s.ToUpper().EndsWith(".OTH") || s.ToUpper().EndsWith(".P12") || s.ToUpper().EndsWith(".P7") || s.ToUpper().EndsWith(".P7B") || s.ToUpper().EndsWith(".P7C") || s.ToUpper().EndsWith(".PAC") || s.ToUpper().EndsWith(".PAGE") || s.ToUpper().EndsWith(".PEM") || s.ToUpper().EndsWith(".PHP") || s.ToUpper().EndsWith(".PHP2") || s.ToUpper().EndsWith(".PHP3") || s.ToUpper().EndsWith(".PHP4") || s.ToUpper().EndsWith(".PHP5") || s.ToUpper().EndsWith(".PHTM") || s.ToUpper().EndsWith(".PHTML") || s.ToUpper().EndsWith(".PPTHTML") || s.ToUpper().EndsWith(".PPTMHTML") || s.ToUpper().EndsWith(".PRF") || s.ToUpper().EndsWith(".PRO") || s.ToUpper().EndsWith(".PSP") || s.ToUpper().EndsWith(".PTW") || s.ToUpper().EndsWith(".PUB") || s.ToUpper().EndsWith(".QBO") || s.ToUpper().EndsWith(".QBX") || s.ToUpper().EndsWith(".QF") || s.ToUpper().EndsWith(".QRM") || s.ToUpper().EndsWith(".RFLW") || s.ToUpper().EndsWith(".RHTML") || s.ToUpper().EndsWith(".RJS") || s.ToUpper().EndsWith(".RSS") || s.ToUpper().EndsWith(".RT") || s.ToUpper().EndsWith(".RW3") || s.ToUpper().EndsWith(".RWP") || s.ToUpper().EndsWith(".RWSW") || s.ToUpper().EndsWith(".RWTHEME") || s.ToUpper().EndsWith(".SASS") || s.ToUpper().EndsWith(".SAVEDDECK") || s.ToUpper().EndsWith(".SCSS") || s.ToUpper().EndsWith(".SDB") || s.ToUpper().EndsWith(".SEAM") || s.ToUpper().EndsWith(".SHT") || s.ToUpper().EndsWith(".SHTM") || s.ToUpper().EndsWith(".SHTML") || s.ToUpper().EndsWith(".SITE") || s.ToUpper().EndsWith(".SITEMAP") || s.ToUpper().EndsWith(".SITES") || s.ToUpper().EndsWith(".SITES2") || s.ToUpper().EndsWith(".SPARKLE") || s.ToUpper().EndsWith(".SPC") || s.ToUpper().EndsWith(".SRF") || s.ToUpper().EndsWith(".SSP") || s.ToUpper().EndsWith(".STC") || s.ToUpper().EndsWith(".STL") || s.ToUpper().EndsWith(".STM") || s.ToUpper().EndsWith(".STML") || s.ToUpper().EndsWith(".STP") || s.ToUpper().EndsWith(".STRM") || s.ToUpper().EndsWith(".SUCK") || s.ToUpper().EndsWith(".SVC") || s.ToUpper().EndsWith(".SVR") || s.ToUpper().EndsWith(".SWZ") || s.ToUpper().EndsWith(".TPL") || s.ToUpper().EndsWith(".TVPI") || s.ToUpper().EndsWith(".TVVI") || s.ToUpper().EndsWith(".UCF") || s.ToUpper().EndsWith(".UHTML") || s.ToUpper().EndsWith(".URL") || s.ToUpper().EndsWith(".VBD") || s.ToUpper().EndsWith(".VBHTML") || s.ToUpper().EndsWith(".VDW") || s.ToUpper().EndsWith(".VLP") || s.ToUpper().EndsWith(".VRML") || s.ToUpper().EndsWith(".VRT") || s.ToUpper().EndsWith(".VSDISCO") || s.ToUpper().EndsWith(".WBS") || s.ToUpper().EndsWith(".WBXML") || s.ToUpper().EndsWith(".WDGT") || s.ToUpper().EndsWith(".WEB") || s.ToUpper().EndsWith(".WEBARCHIVE") || s.ToUpper().EndsWith(".WEBARCHIVEXML") || s.ToUpper().EndsWith(".WEBBOOKMARK") || s.ToUpper().EndsWith(".WEBHISTORY") || s.ToUpper().EndsWith(".WEBLOC") || s.ToUpper().EndsWith(".WEBSITE") || s.ToUpper().EndsWith(".WGP") || s.ToUpper().EndsWith(".WGT") || s.ToUpper().EndsWith(".WHTT") || s.ToUpper().EndsWith(".WIDGET") || s.ToUpper().EndsWith(".WML") || s.ToUpper().EndsWith(".WN") || s.ToUpper().EndsWith(".WOA") || s.ToUpper().EndsWith(".WPP") || s.ToUpper().EndsWith(".WPX") || s.ToUpper().EndsWith(".WRF") || s.ToUpper().EndsWith(".WSDL") || s.ToUpper().EndsWith(".XBEL") || s.ToUpper().EndsWith(".XBL") || s.ToUpper().EndsWith(".XFDL") || s.ToUpper().EndsWith(".XHT") || s.ToUpper().EndsWith(".XHTM") || s.ToUpper().EndsWith(".XHTML") || s.ToUpper().EndsWith(".XPD") || s.ToUpper().EndsWith(".XSS") || s.ToUpper().EndsWith(".XUL") || s.ToUpper().EndsWith(".XWS") || s.ToUpper().EndsWith(".ZFO") || s.ToUpper().EndsWith(".ZHTML") || s.ToUpper().EndsWith(".ZHTML") || s.ToUpper().EndsWith(".ZUL") || s.ToUpper().EndsWith(".ZVZ"));
                        webFiles = e.ToList<string>();
                        //Console.WriteLine("Can you see me? " + aPath + " webFiles size: " + webFiles.Count);
                    }
                    //IEnumerable<string> e = Directory.GetFiles(aPath, "*.*", SearchOption.AllDirectories).Where(s => s.ToUpper().EndsWith(".A4P") || s.ToUpper().EndsWith(".A5W") || s.ToUpper().EndsWith(".ADR") || s.ToUpper().EndsWith(".AEX") || s.ToUpper().EndsWith(".ALX") || s.ToUpper().EndsWith(".AN") || s.ToUpper().EndsWith(".AP") || s.ToUpper().EndsWith(".APPCACHE") || s.ToUpper().EndsWith(".ARO") || s.ToUpper().EndsWith(".ASA") || s.ToUpper().EndsWith(".ASAX") || s.ToUpper().EndsWith(".ASCX") || s.ToUpper().EndsWith(".ASHX") || s.ToUpper().EndsWith(".ASMX") || s.ToUpper().EndsWith(".ASP") || s.ToUpper().EndsWith(".ASPX") || s.ToUpper().EndsWith(".ASR") || s.ToUpper().EndsWith(".ATOM") || s.ToUpper().EndsWith(".ATT") || s.ToUpper().EndsWith(".AWM") || s.ToUpper().EndsWith(".AXD") || s.ToUpper().EndsWith(".BML") || s.ToUpper().EndsWith(".BOK") || s.ToUpper().EndsWith(".BR") || s.ToUpper().EndsWith(".BROWSER") || s.ToUpper().EndsWith(".BTAPP") || s.ToUpper().EndsWith(".BWP") || s.ToUpper().EndsWith(".CCBJS") || s.ToUpper().EndsWith(".CDF") || s.ToUpper().EndsWith(".CER") || s.ToUpper().EndsWith(".CFM") || s.ToUpper().EndsWith(".CFML") || s.ToUpper().EndsWith(".CHA") || s.ToUpper().EndsWith(".CHAT") || s.ToUpper().EndsWith(".CHM") || s.ToUpper().EndsWith(".CMS") || s.ToUpper().EndsWith(".CODASITE") || s.ToUpper().EndsWith(".COMPRESSED") || s.ToUpper().EndsWith(".CON") || s.ToUpper().EndsWith(".CPG") || s.ToUpper().EndsWith(".CPHD") || s.ToUpper().EndsWith(".CRL") || s.ToUpper().EndsWith(".CRT") || s.ToUpper().EndsWith(".CSHTML") || s.ToUpper().EndsWith(".CSP") || s.ToUpper().EndsWith(".CSR") || s.ToUpper().EndsWith(".CSS") || s.ToUpper().EndsWith(".DAP") || s.ToUpper().EndsWith(".DBM") || s.ToUpper().EndsWith(".DCR") || s.ToUpper().EndsWith(".DER") || s.ToUpper().EndsWith(".DHTML") || s.ToUpper().EndsWith(".DISCO") || s.ToUpper().EndsWith(".DISCOMAP") || s.ToUpper().EndsWith(".DLL") || s.ToUpper().EndsWith(".DML") || s.ToUpper().EndsWith(".DO") || s.ToUpper().EndsWith(".DOCHTML") || s.ToUpper().EndsWith(".DOCMHTML") || s.ToUpper().EndsWith(".DOTHTML") || s.ToUpper().EndsWith(".DOWNLOAD") || s.ToUpper().EndsWith(".DWT") || s.ToUpper().EndsWith(".ECE") || s.ToUpper().EndsWith(".EDGE") || s.ToUpper().EndsWith(".EPIBRW") || s.ToUpper().EndsWith(".ESPROJ") || s.ToUpper().EndsWith(".EWP") || s.ToUpper().EndsWith(".FCGI") || s.ToUpper().EndsWith(".FMP") || s.ToUpper().EndsWith(".FREEWAY") || s.ToUpper().EndsWith(".FWP") || s.ToUpper().EndsWith(".FWTB") || s.ToUpper().EndsWith(".FWTEMPLATE") || s.ToUpper().EndsWith(".FWTEMPLATEB") || s.ToUpper().EndsWith(".GNE") || s.ToUpper().EndsWith(".GSP") || s.ToUpper().EndsWith(".GSP") || s.ToUpper().EndsWith(".HAR") || s.ToUpper().EndsWith(".HDM") || s.ToUpper().EndsWith(".HDML") || s.ToUpper().EndsWith(".HTACCESS") || s.ToUpper().EndsWith(".HTC") || s.ToUpper().EndsWith(".HTM") || s.ToUpper().EndsWith(".HTML") || s.ToUpper().EndsWith(".HTX") || s.ToUpper().EndsWith(".HXS") || s.ToUpper().EndsWith(".HYPE") || s.ToUpper().EndsWith(".HYPERESOURCES") || s.ToUpper().EndsWith(".HYPESYMBOL") || s.ToUpper().EndsWith(".HYPETEMPLATE") || s.ToUpper().EndsWith(".IDC") || s.ToUpper().EndsWith(".IQY") || s.ToUpper().EndsWith(".ITMS") || s.ToUpper().EndsWith(".ITPC") || s.ToUpper().EndsWith(".IWDGT") || s.ToUpper().EndsWith(".JCZ") || s.ToUpper().EndsWith(".JHTML") || s.ToUpper().EndsWith(".JNLP") || s.ToUpper().EndsWith(".JS") || s.ToUpper().EndsWith(".JSON") || s.ToUpper().EndsWith(".JSP") || s.ToUpper().EndsWith(".JSPA") || s.ToUpper().EndsWith(".JSPX") || s.ToUpper().EndsWith(".JSS") || s.ToUpper().EndsWith(".JST") || s.ToUpper().EndsWith(".JVS") || s.ToUpper().EndsWith(".JWS") || s.ToUpper().EndsWith(".KIT") || s.ToUpper().EndsWith(".LASSO") || s.ToUpper().EndsWith(".LBC") || s.ToUpper().EndsWith(".LESS") || s.ToUpper().EndsWith(".MAFF") || s.ToUpper().EndsWith(".MAP") || s.ToUpper().EndsWith(".MAPX") || s.ToUpper().EndsWith(".MASTER") || s.ToUpper().EndsWith(".MHT") || s.ToUpper().EndsWith(".MHTML") || s.ToUpper().EndsWith(".MJS") || s.ToUpper().EndsWith(".MOZ") || s.ToUpper().EndsWith(".MSPX") || s.ToUpper().EndsWith(".MUSE") || s.ToUpper().EndsWith(".MVC") || s.ToUpper().EndsWith(".MVR") || s.ToUpper().EndsWith(".NOD") || s.ToUpper().EndsWith(".NXG") || s.ToUpper().EndsWith(".NZB") || s.ToUpper().EndsWith(".OAM") || s.ToUpper().EndsWith(".OBML") || s.ToUpper().EndsWith(".OBML15") || s.ToUpper().EndsWith(".OBML16") || s.ToUpper().EndsWith(".OGNC") || s.ToUpper().EndsWith(".OLP") || s.ToUpper().EndsWith(".OPML") || s.ToUpper().EndsWith(".OTH") || s.ToUpper().EndsWith(".P12") || s.ToUpper().EndsWith(".P7") || s.ToUpper().EndsWith(".P7B") || s.ToUpper().EndsWith(".P7C") || s.ToUpper().EndsWith(".PAC") || s.ToUpper().EndsWith(".PAGE") || s.ToUpper().EndsWith(".PEM") || s.ToUpper().EndsWith(".PHP") || s.ToUpper().EndsWith(".PHP2") || s.ToUpper().EndsWith(".PHP3") || s.ToUpper().EndsWith(".PHP4") || s.ToUpper().EndsWith(".PHP5") || s.ToUpper().EndsWith(".PHTM") || s.ToUpper().EndsWith(".PHTML") || s.ToUpper().EndsWith(".PPTHTML") || s.ToUpper().EndsWith(".PPTMHTML") || s.ToUpper().EndsWith(".PRF") || s.ToUpper().EndsWith(".PRO") || s.ToUpper().EndsWith(".PSP") || s.ToUpper().EndsWith(".PTW") || s.ToUpper().EndsWith(".PUB") || s.ToUpper().EndsWith(".QBO") || s.ToUpper().EndsWith(".QBX") || s.ToUpper().EndsWith(".QF") || s.ToUpper().EndsWith(".QRM") || s.ToUpper().EndsWith(".RFLW") || s.ToUpper().EndsWith(".RHTML") || s.ToUpper().EndsWith(".RJS") || s.ToUpper().EndsWith(".RSS") || s.ToUpper().EndsWith(".RT") || s.ToUpper().EndsWith(".RW3") || s.ToUpper().EndsWith(".RWP") || s.ToUpper().EndsWith(".RWSW") || s.ToUpper().EndsWith(".RWTHEME") || s.ToUpper().EndsWith(".SASS") || s.ToUpper().EndsWith(".SAVEDDECK") || s.ToUpper().EndsWith(".SCSS") || s.ToUpper().EndsWith(".SDB") || s.ToUpper().EndsWith(".SEAM") || s.ToUpper().EndsWith(".SHT") || s.ToUpper().EndsWith(".SHTM") || s.ToUpper().EndsWith(".SHTML") || s.ToUpper().EndsWith(".SITE") || s.ToUpper().EndsWith(".SITEMAP") || s.ToUpper().EndsWith(".SITES") || s.ToUpper().EndsWith(".SITES2") || s.ToUpper().EndsWith(".SPARKLE") || s.ToUpper().EndsWith(".SPC") || s.ToUpper().EndsWith(".SRF") || s.ToUpper().EndsWith(".SSP") || s.ToUpper().EndsWith(".STC") || s.ToUpper().EndsWith(".STL") || s.ToUpper().EndsWith(".STM") || s.ToUpper().EndsWith(".STML") || s.ToUpper().EndsWith(".STP") || s.ToUpper().EndsWith(".STRM") || s.ToUpper().EndsWith(".SUCK") || s.ToUpper().EndsWith(".SVC") || s.ToUpper().EndsWith(".SVR") || s.ToUpper().EndsWith(".SWZ") || s.ToUpper().EndsWith(".TPL") || s.ToUpper().EndsWith(".TVPI") || s.ToUpper().EndsWith(".TVVI") || s.ToUpper().EndsWith(".UCF") || s.ToUpper().EndsWith(".UHTML") || s.ToUpper().EndsWith(".URL") || s.ToUpper().EndsWith(".VBD") || s.ToUpper().EndsWith(".VBHTML") || s.ToUpper().EndsWith(".VDW") || s.ToUpper().EndsWith(".VLP") || s.ToUpper().EndsWith(".VRML") || s.ToUpper().EndsWith(".VRT") || s.ToUpper().EndsWith(".VSDISCO") || s.ToUpper().EndsWith(".WBS") || s.ToUpper().EndsWith(".WBXML") || s.ToUpper().EndsWith(".WDGT") || s.ToUpper().EndsWith(".WEB") || s.ToUpper().EndsWith(".WEBARCHIVE") || s.ToUpper().EndsWith(".WEBARCHIVEXML") || s.ToUpper().EndsWith(".WEBBOOKMARK") || s.ToUpper().EndsWith(".WEBHISTORY") || s.ToUpper().EndsWith(".WEBLOC") || s.ToUpper().EndsWith(".WEBSITE") || s.ToUpper().EndsWith(".WGP") || s.ToUpper().EndsWith(".WGT") || s.ToUpper().EndsWith(".WHTT") || s.ToUpper().EndsWith(".WIDGET") || s.ToUpper().EndsWith(".WML") || s.ToUpper().EndsWith(".WN") || s.ToUpper().EndsWith(".WOA") || s.ToUpper().EndsWith(".WPP") || s.ToUpper().EndsWith(".WPX") || s.ToUpper().EndsWith(".WRF") || s.ToUpper().EndsWith(".WSDL") || s.ToUpper().EndsWith(".XBEL") || s.ToUpper().EndsWith(".XBL") || s.ToUpper().EndsWith(".XFDL") || s.ToUpper().EndsWith(".XHT") || s.ToUpper().EndsWith(".XHTM") || s.ToUpper().EndsWith(".XHTML") || s.ToUpper().EndsWith(".XPD") || s.ToUpper().EndsWith(".XSS") || s.ToUpper().EndsWith(".XUL") || s.ToUpper().EndsWith(".XWS") || s.ToUpper().EndsWith(".ZFO") || s.ToUpper().EndsWith(".ZHTML") || s.ToUpper().EndsWith(".ZHTML") || s.ToUpper().EndsWith(".ZUL") || s.ToUpper().EndsWith(".ZVZ"));
                    //List<string> webFiles = e.ToList<string>();

                    //List<string> webFiles = getWebFiles(aPath); // currently returing all these weird non web files
                    /*List<string> allFiles = GetAllAccessibleFiles(aPath, null);
                    List<string> webFiles = new List<string>();

                    foreach (string file in allFiles)
                    {
                        if (file.ToUpper().EndsWith(".A4P") || file.ToUpper().EndsWith(".A5W") || file.ToUpper().EndsWith(".ADR") || file.ToUpper().EndsWith(".AEX") || file.ToUpper().EndsWith(".ALX") || file.ToUpper().EndsWith(".AN") || file.ToUpper().EndsWith(".AP") || file.ToUpper().EndsWith(".APPCACHE") || file.ToUpper().EndsWith(".ARO") || file.ToUpper().EndsWith(".ASA") || file.ToUpper().EndsWith(".ASAX") || file.ToUpper().EndsWith(".ASCX") || file.ToUpper().EndsWith(".ASHX") || file.ToUpper().EndsWith(".ASMX") || file.ToUpper().EndsWith(".ASP") || file.ToUpper().EndsWith(".ASPX") || file.ToUpper().EndsWith(".ASR") || file.ToUpper().EndsWith(".ATOM") || file.ToUpper().EndsWith(".ATT") || file.ToUpper().EndsWith(".AWM") || file.ToUpper().EndsWith(".AXD") || file.ToUpper().EndsWith(".BML") || file.ToUpper().EndsWith(".BOK") || file.ToUpper().EndsWith(".BR") || file.ToUpper().EndsWith(".BROWSER") || file.ToUpper().EndsWith(".BTAPP") || file.ToUpper().EndsWith(".BWP") || file.ToUpper().EndsWith(".CCBJS") || file.ToUpper().EndsWith(".CDF") || file.ToUpper().EndsWith(".CER") || file.ToUpper().EndsWith(".CFM") || file.ToUpper().EndsWith(".CFML") || file.ToUpper().EndsWith(".CHA") || file.ToUpper().EndsWith(".CHAT") || file.ToUpper().EndsWith(".CHM") || file.ToUpper().EndsWith(".CMS") || file.ToUpper().EndsWith(".CODASITE") || file.ToUpper().EndsWith(".COMPRESSED") || file.ToUpper().EndsWith(".CON") || file.ToUpper().EndsWith(".CPG") || file.ToUpper().EndsWith(".CPHD") || file.ToUpper().EndsWith(".CRL") || file.ToUpper().EndsWith(".CRT") || file.ToUpper().EndsWith(".CSHTML") || file.ToUpper().EndsWith(".CSP") || file.ToUpper().EndsWith(".CSR") || file.ToUpper().EndsWith(".CSS") || file.ToUpper().EndsWith(".DAP") || file.ToUpper().EndsWith(".DBM") || file.ToUpper().EndsWith(".DCR") || file.ToUpper().EndsWith(".DER") || file.ToUpper().EndsWith(".DHTML") || file.ToUpper().EndsWith(".DISCO") || file.ToUpper().EndsWith(".DISCOMAP") || file.ToUpper().EndsWith(".DML") || file.ToUpper().EndsWith(".DO") || file.ToUpper().EndsWith(".DOCHTML") || file.ToUpper().EndsWith(".DOCMHTML") || file.ToUpper().EndsWith(".DOTHTML") || file.ToUpper().EndsWith(".DOWNLOAD") || file.ToUpper().EndsWith(".DWT") || file.ToUpper().EndsWith(".ECE") || file.ToUpper().EndsWith(".EDGE") || file.ToUpper().EndsWith(".EPIBRW") || file.ToUpper().EndsWith(".ESPROJ") || file.ToUpper().EndsWith(".EWP") || file.ToUpper().EndsWith(".FCGI") || file.ToUpper().EndsWith(".FMP") || file.ToUpper().EndsWith(".FREEWAY") || file.ToUpper().EndsWith(".FWP") || file.ToUpper().EndsWith(".FWTB") || file.ToUpper().EndsWith(".FWTEMPLATE") || file.ToUpper().EndsWith(".FWTEMPLATEB") || file.ToUpper().EndsWith(".GNE") || file.ToUpper().EndsWith(".GSP") || file.ToUpper().EndsWith(".GSP") || file.ToUpper().EndsWith(".HAR") || file.ToUpper().EndsWith(".HDM") || file.ToUpper().EndsWith(".HDML") || file.ToUpper().EndsWith(".HTACCESS") || file.ToUpper().EndsWith(".HTC") || file.ToUpper().EndsWith(".HTM") || file.ToUpper().EndsWith(".HTML") || file.ToUpper().EndsWith(".HTX") || file.ToUpper().EndsWith(".HXS") || file.ToUpper().EndsWith(".HYPE") || file.ToUpper().EndsWith(".HYPERESOURCES") || file.ToUpper().EndsWith(".HYPESYMBOL") || file.ToUpper().EndsWith(".HYPETEMPLATE") || file.ToUpper().EndsWith(".IDC") || file.ToUpper().EndsWith(".IQY") || file.ToUpper().EndsWith(".ITMS") || file.ToUpper().EndsWith(".ITPC") || file.ToUpper().EndsWith(".IWDGT") || file.ToUpper().EndsWith(".JCZ") || file.ToUpper().EndsWith(".JHTML") || file.ToUpper().EndsWith(".JNLP") || file.ToUpper().EndsWith(".JS") || file.ToUpper().EndsWith(".JSON") || file.ToUpper().EndsWith(".JSP") || file.ToUpper().EndsWith(".JSPA") || file.ToUpper().EndsWith(".JSPX") || file.ToUpper().EndsWith(".JSS") || file.ToUpper().EndsWith(".JST") || file.ToUpper().EndsWith(".JVS") || file.ToUpper().EndsWith(".JWS") || file.ToUpper().EndsWith(".KIT") || file.ToUpper().EndsWith(".LASSO") || file.ToUpper().EndsWith(".LBC") || file.ToUpper().EndsWith(".LESS") || file.ToUpper().EndsWith(".MAFF") || file.ToUpper().EndsWith(".MAP") || file.ToUpper().EndsWith(".MAPX") || file.ToUpper().EndsWith(".MASTER") || file.ToUpper().EndsWith(".MHT") || file.ToUpper().EndsWith(".MHTML") || file.ToUpper().EndsWith(".MJS") || file.ToUpper().EndsWith(".MOZ") || file.ToUpper().EndsWith(".MSPX") || file.ToUpper().EndsWith(".MUSE") || file.ToUpper().EndsWith(".MVC") || file.ToUpper().EndsWith(".MVR") || file.ToUpper().EndsWith(".NOD") || file.ToUpper().EndsWith(".NXG") || file.ToUpper().EndsWith(".NZB") || file.ToUpper().EndsWith(".OAM") || file.ToUpper().EndsWith(".OBML") || file.ToUpper().EndsWith(".OBML15") || file.ToUpper().EndsWith(".OBML16") || file.ToUpper().EndsWith(".OGNC") || file.ToUpper().EndsWith(".OLP") || file.ToUpper().EndsWith(".OPML") || file.ToUpper().EndsWith(".OTH") || file.ToUpper().EndsWith(".P12") || file.ToUpper().EndsWith(".P7") || file.ToUpper().EndsWith(".P7B") || file.ToUpper().EndsWith(".P7C") || file.ToUpper().EndsWith(".PAC") || file.ToUpper().EndsWith(".PAGE") || file.ToUpper().EndsWith(".PEM") || file.ToUpper().EndsWith(".PHP") || file.ToUpper().EndsWith(".PHP2") || file.ToUpper().EndsWith(".PHP3") || file.ToUpper().EndsWith(".PHP4") || file.ToUpper().EndsWith(".PHP5") || file.ToUpper().EndsWith(".PHTM") || file.ToUpper().EndsWith(".PHTML") || file.ToUpper().EndsWith(".PPTHTML") || file.ToUpper().EndsWith(".PPTMHTML") || file.ToUpper().EndsWith(".PRF") || file.ToUpper().EndsWith(".PRO") || file.ToUpper().EndsWith(".PSP") || file.ToUpper().EndsWith(".PTW") || file.ToUpper().EndsWith(".PUB") || file.ToUpper().EndsWith(".QBO") || file.ToUpper().EndsWith(".QBX") || file.ToUpper().EndsWith(".QF") || file.ToUpper().EndsWith(".QRM") || file.ToUpper().EndsWith(".RFLW") || file.ToUpper().EndsWith(".RHTML") || file.ToUpper().EndsWith(".RJS") || file.ToUpper().EndsWith(".RSS") || file.ToUpper().EndsWith(".RT") || file.ToUpper().EndsWith(".RW3") || file.ToUpper().EndsWith(".RWP") || file.ToUpper().EndsWith(".RWSW") || file.ToUpper().EndsWith(".RWTHEME") || file.ToUpper().EndsWith(".SASS") || file.ToUpper().EndsWith(".SAVEDDECK") || file.ToUpper().EndsWith(".SCSS") || file.ToUpper().EndsWith(".SDB") || file.ToUpper().EndsWith(".SEAM") || file.ToUpper().EndsWith(".SHT") || file.ToUpper().EndsWith(".SHTM") || file.ToUpper().EndsWith(".SHTML") || file.ToUpper().EndsWith(".SITE") || file.ToUpper().EndsWith(".SITEMAP") || file.ToUpper().EndsWith(".SITES") || file.ToUpper().EndsWith(".SITES2") || file.ToUpper().EndsWith(".SPARKLE") || file.ToUpper().EndsWith(".SPC") || file.ToUpper().EndsWith(".SRF") || file.ToUpper().EndsWith(".SSP") || file.ToUpper().EndsWith(".STC") || file.ToUpper().EndsWith(".STL") || file.ToUpper().EndsWith(".STM") || file.ToUpper().EndsWith(".STML") || file.ToUpper().EndsWith(".STP") || file.ToUpper().EndsWith(".STRM") || file.ToUpper().EndsWith(".SUCK") || file.ToUpper().EndsWith(".SVC") || file.ToUpper().EndsWith(".SVR") || file.ToUpper().EndsWith(".SWZ") || file.ToUpper().EndsWith(".TPL") || file.ToUpper().EndsWith(".TVPI") || file.ToUpper().EndsWith(".TVVI") || file.ToUpper().EndsWith(".UCF") || file.ToUpper().EndsWith(".UHTML") || file.ToUpper().EndsWith(".URL") || file.ToUpper().EndsWith(".VBD") || file.ToUpper().EndsWith(".VBHTML") || file.ToUpper().EndsWith(".VDW") || file.ToUpper().EndsWith(".VLP") || file.ToUpper().EndsWith(".VRML") || file.ToUpper().EndsWith(".VRT") || file.ToUpper().EndsWith(".VSDISCO") || file.ToUpper().EndsWith(".WBS") || file.ToUpper().EndsWith(".WBXML") || file.ToUpper().EndsWith(".WDGT") || file.ToUpper().EndsWith(".WEB") || file.ToUpper().EndsWith(".WEBARCHIVE") || file.ToUpper().EndsWith(".WEBARCHIVEXML") || file.ToUpper().EndsWith(".WEBBOOKMARK") || file.ToUpper().EndsWith(".WEBHISTORY") || file.ToUpper().EndsWith(".WEBLOC") || file.ToUpper().EndsWith(".WEBSITE") || file.ToUpper().EndsWith(".WGP") || file.ToUpper().EndsWith(".WGT") || file.ToUpper().EndsWith(".WHTT") || file.ToUpper().EndsWith(".WIDGET") || file.ToUpper().EndsWith(".WML") || file.ToUpper().EndsWith(".WN") || file.ToUpper().EndsWith(".WOA") || file.ToUpper().EndsWith(".WPP") || file.ToUpper().EndsWith(".WPX") || file.ToUpper().EndsWith(".WRF") || file.ToUpper().EndsWith(".WSDL") || file.ToUpper().EndsWith(".XBEL") || file.ToUpper().EndsWith(".XBL") || file.ToUpper().EndsWith(".XFDL") || file.ToUpper().EndsWith(".XHT") || file.ToUpper().EndsWith(".XHTM") || file.ToUpper().EndsWith(".XHTML") || file.ToUpper().EndsWith(".XPD") || file.ToUpper().EndsWith(".XSS") || file.ToUpper().EndsWith(".XUL") || file.ToUpper().EndsWith(".XWS") || file.ToUpper().EndsWith(".ZFO") || file.ToUpper().EndsWith(".ZHTML") || file.ToUpper().EndsWith(".ZHTML") || file.ToUpper().EndsWith(".ZUL") || file.ToUpper().EndsWith(".ZVZ"))
                        {
                            webFiles.Add(file);
                        }
                    }*/


                    foreach (string webFile in webFiles)
                    {
                        //Console.WriteLine("Web file: " + webFile);


                        // FIRST CHECK FOR URLS USING DEFAULT IIS DIRECTORY STRUCTURE

                        if (webConfig == "" && webFile.Contains("inetpub") && webFile.Contains("wwwroot"))
                        {



                            DirectoryInfo currentDirectoryInfo = new DirectoryInfo(webFile);

                            // lets walk up the file path to identify where the root of the IIS server is located
                            for (DirectoryInfo nodeInfo = currentDirectoryInfo; nodeInfo.Parent != null; nodeInfo = nodeInfo.Parent)
                            {
                                try
                                {

                                    String grandParentNode = nodeInfo.Parent.Parent.Name;
                                    String parentNode = nodeInfo.Parent.Name;
                                    if (grandParentNode == "inetpub" && parentNode == "wwwroot")
                                    {

                                        int parentIndex = webFile.IndexOf("wwwroot");

                                        defaultIISPaths.Add(webFile.Substring(0,parentIndex+parentNode.Length));

                                        try
                                        {
                                            // empty if there's no web.config
                                            foreach (string binding in goodBindings)
                                            {


                                                string potentialURL = binding + "/" + webFile.Substring(parentIndex + 8, webFile.Length - parentIndex - 8).Replace("\\", "/");

                                                //Console.WriteLine("Potential URL without web.config: " + potentialURL);
                                                potentialURLs.Add(potentialURL);

                                            }


                                        }
                                        catch (Exception) { }





                                    }
                                }
                                catch (Exception ee)
                                {
                                    continue;
                                }


                            }


                        } // AFTER FINDING URLS USING THE DEFAULT IIS DIRECTORY STRUCTURE WE THEN TRY USING WEB.CONFIG PROPERTIES
                        else if (webConfig != "")
                        {

                            foreach (string binding in goodBindings)
                            {


                                foreach (KeyValuePair<string, string> entry in applicationPaths)
                                {

                                    // we're assuming physicalPath doesn't end with a \
                                    //string potentialURL = binding +entry.Value + trimmed.Replace("\\", "/");

                                    DirectoryInfo currentDirectoryInfo = new DirectoryInfo(webFile);

                                    // lets walk up the file path to identify where the root of the IIS server is located
                                    for (DirectoryInfo nodeInfo = currentDirectoryInfo; nodeInfo.Parent != null; nodeInfo = nodeInfo.Parent)
                                    {
                                        try
                                        {
                                            DirectoryInfo parentNode = nodeInfo.Parent;


                                            // if you're within the IIS root
                                            // NOTE: What if physicalPath="C:\inetpub\wwwroot"? Our filepaths are on a shared drive, \\asdf\jjfj$\inetpub\wwwroot != C:\inetpub\wwwroot and this check will fail.
                                            //       Since a mount can be placed in any dir, there's no way to translate the shared drive filepath to the IIS server's local filepath....
                                            //       I think this means that physicalPath is not a helpful web.config property and we must might be in trouble
                                            //       Idea: take last path name e.g. wwwroot and search share drive for that folder
                                            //if (parentNode.FullName == entry.Key)
                                           

                                            if (parentNode.Name.Replace("\\","") == entry.Key.Substring(entry.Key.LastIndexOf("\\"),entry.Key.Length - entry.Key.LastIndexOf("\\")).Replace("\\",""))
                                            {
                                                //Console.WriteLine("We're within teh IIS root! " + entry.Key);
                                                //Console.WriteLine("entry.Key.Substring(entry.Key.LastIndexOf(slash),entry.Key.Length - entry.Key.LastIndexOf(slash))" + entry.Key.Substring(entry.Key.LastIndexOf("\\"), entry.Key.Length - entry.Key.LastIndexOf("\\")));
                                                int parentIndex = webFile.IndexOf(parentNode.Name);

                                                string potentialURL = binding + entry.Value + webFile.Substring(parentIndex + parentNode.Name.Length, webFile.Length - parentIndex - parentNode.Name.Length).Replace("\\", "/");
                                                //Console.WriteLine("Sexy URL! " + potentialURL);
                                                potentialURLs.Add(potentialURL);
                                            }


                                        }
                                        catch (Exception ee)
                                        {
                                            continue;
                                        }


                                    }

                                }



                            }
                        }




                    }
                }
                catch (Exception) { continue; }
                


            }

            // List default IIS paths if there's no web.config
            foreach(string path in defaultIISPaths.Distinct())
            {
                Console.WriteLine("\nDefault IIS directory structure detected:\n" + path);
            }


            List<string> potentialURLsUnique = potentialURLs.Distinct().ToList();

            for (int i = 0; i < potentialURLsUnique.Count; i++)
            {
                if (potentialURLsUnique[i].Contains("//"))
                {
                    potentialURLsUnique[i] = potentialURLsUnique[i].Replace("//", "/");
                }
            }

            // NOTE: i have a feeling that we need to encode the url first. 
            // stdout hangs on correctly formatted urls but quickly skips over a url containing a space
            foreach (string potentialURL in potentialURLsUnique) {
                
                try
                {
                    if (isURLExist("http://" + potentialURL))
                    {
                        Console.WriteLine("Valid URL: " + "http://" + potentialURL);
                    }

                    Console.WriteLine("Potential URL: " + potentialURL);

                }
                catch (Exception) { continue; }

            }
        }

        
        public static List<string> getWebFiles(string rootPath, List<string> alreadyFound = null)
        {
            try
            {
                if (alreadyFound == null)
                    alreadyFound = new List<string>();
                DirectoryInfo di = new DirectoryInfo(rootPath);
                var dirs = di.EnumerateDirectories();
                foreach (DirectoryInfo dir in dirs)
                {
                    if (!((dir.Attributes & FileAttributes.Hidden) == FileAttributes.Hidden))
                    {
                        alreadyFound = GetAllAccessibleFiles(dir.FullName, alreadyFound);
                    }
                }

                var files = Directory.GetFiles(rootPath);
                foreach (string s in files)
                {
                    if (s.ToUpper().EndsWith(".A4P") || s.ToUpper().EndsWith(".A5W") || s.ToUpper().EndsWith(".ADR") || s.ToUpper().EndsWith(".AEX") || s.ToUpper().EndsWith(".ALX") || s.ToUpper().EndsWith(".AN") || s.ToUpper().EndsWith(".AP") || s.ToUpper().EndsWith(".APPCACHE") || s.ToUpper().EndsWith(".ARO") || s.ToUpper().EndsWith(".ASA") || s.ToUpper().EndsWith(".ASAX") || s.ToUpper().EndsWith(".ASCX") || s.ToUpper().EndsWith(".ASHX") || s.ToUpper().EndsWith(".ASMX") || s.ToUpper().EndsWith(".ASP") || s.ToUpper().EndsWith(".ASPX") || s.ToUpper().EndsWith(".ASR") || s.ToUpper().EndsWith(".ATOM") || s.ToUpper().EndsWith(".ATT") || s.ToUpper().EndsWith(".AWM") || s.ToUpper().EndsWith(".AXD") || s.ToUpper().EndsWith(".BML") || s.ToUpper().EndsWith(".BOK") || s.ToUpper().EndsWith(".BR") || s.ToUpper().EndsWith(".BROWSER") || s.ToUpper().EndsWith(".BTAPP") || s.ToUpper().EndsWith(".BWP") || s.ToUpper().EndsWith(".CCBJS") || s.ToUpper().EndsWith(".CDF") || s.ToUpper().EndsWith(".CER") || s.ToUpper().EndsWith(".CFM") || s.ToUpper().EndsWith(".CFML") || s.ToUpper().EndsWith(".CHA") || s.ToUpper().EndsWith(".CHAT") || s.ToUpper().EndsWith(".CHM") || s.ToUpper().EndsWith(".CMS") || s.ToUpper().EndsWith(".CODASITE") || s.ToUpper().EndsWith(".COMPRESSED") || s.ToUpper().EndsWith(".CON") || s.ToUpper().EndsWith(".CPG") || s.ToUpper().EndsWith(".CPHD") || s.ToUpper().EndsWith(".CRL") || s.ToUpper().EndsWith(".CRT") || s.ToUpper().EndsWith(".CSHTML") || s.ToUpper().EndsWith(".CSP") || s.ToUpper().EndsWith(".CSR") || s.ToUpper().EndsWith(".CSS") || s.ToUpper().EndsWith(".DAP") || s.ToUpper().EndsWith(".DBM") || s.ToUpper().EndsWith(".DCR") || s.ToUpper().EndsWith(".DER") || s.ToUpper().EndsWith(".DHTML") || s.ToUpper().EndsWith(".DISCO") || s.ToUpper().EndsWith(".DISCOMAP") || s.ToUpper().EndsWith(".DML") || s.ToUpper().EndsWith(".DO") || s.ToUpper().EndsWith(".DOCHTML") || s.ToUpper().EndsWith(".DOCMHTML") || s.ToUpper().EndsWith(".DOTHTML") || s.ToUpper().EndsWith(".DOWNLOAD") || s.ToUpper().EndsWith(".DWT") || s.ToUpper().EndsWith(".ECE") || s.ToUpper().EndsWith(".EDGE") || s.ToUpper().EndsWith(".EPIBRW") || s.ToUpper().EndsWith(".ESPROJ") || s.ToUpper().EndsWith(".EWP") || s.ToUpper().EndsWith(".FCGI") || s.ToUpper().EndsWith(".FMP") || s.ToUpper().EndsWith(".FREEWAY") || s.ToUpper().EndsWith(".FWP") || s.ToUpper().EndsWith(".FWTB") || s.ToUpper().EndsWith(".FWTEMPLATE") || s.ToUpper().EndsWith(".FWTEMPLATEB") || s.ToUpper().EndsWith(".GNE") || s.ToUpper().EndsWith(".GSP") || s.ToUpper().EndsWith(".GSP") || s.ToUpper().EndsWith(".HAR") || s.ToUpper().EndsWith(".HDM") || s.ToUpper().EndsWith(".HDML") || s.ToUpper().EndsWith(".HTACCESS") || s.ToUpper().EndsWith(".HTC") || s.ToUpper().EndsWith(".HTM") || s.ToUpper().EndsWith(".HTML") || s.ToUpper().EndsWith(".HTX") || s.ToUpper().EndsWith(".HXS") || s.ToUpper().EndsWith(".HYPE") || s.ToUpper().EndsWith(".HYPERESOURCES") || s.ToUpper().EndsWith(".HYPESYMBOL") || s.ToUpper().EndsWith(".HYPETEMPLATE") || s.ToUpper().EndsWith(".IDC") || s.ToUpper().EndsWith(".IQY") || s.ToUpper().EndsWith(".ITMS") || s.ToUpper().EndsWith(".ITPC") || s.ToUpper().EndsWith(".IWDGT") || s.ToUpper().EndsWith(".JCZ") || s.ToUpper().EndsWith(".JHTML") || s.ToUpper().EndsWith(".JNLP") || s.ToUpper().EndsWith(".JS") || s.ToUpper().EndsWith(".JSON") || s.ToUpper().EndsWith(".JSP") || s.ToUpper().EndsWith(".JSPA") || s.ToUpper().EndsWith(".JSPX") || s.ToUpper().EndsWith(".JSS") || s.ToUpper().EndsWith(".JST") || s.ToUpper().EndsWith(".JVS") || s.ToUpper().EndsWith(".JWS") || s.ToUpper().EndsWith(".KIT") || s.ToUpper().EndsWith(".LASSO") || s.ToUpper().EndsWith(".LBC") || s.ToUpper().EndsWith(".LESS") || s.ToUpper().EndsWith(".MAFF") || s.ToUpper().EndsWith(".MAP") || s.ToUpper().EndsWith(".MAPX") || s.ToUpper().EndsWith(".MASTER") || s.ToUpper().EndsWith(".MHT") || s.ToUpper().EndsWith(".MHTML") || s.ToUpper().EndsWith(".MJS") || s.ToUpper().EndsWith(".MOZ") || s.ToUpper().EndsWith(".MSPX") || s.ToUpper().EndsWith(".MUSE") || s.ToUpper().EndsWith(".MVC") || s.ToUpper().EndsWith(".MVR") || s.ToUpper().EndsWith(".NOD") || s.ToUpper().EndsWith(".NXG") || s.ToUpper().EndsWith(".NZB") || s.ToUpper().EndsWith(".OAM") || s.ToUpper().EndsWith(".OBML") || s.ToUpper().EndsWith(".OBML15") || s.ToUpper().EndsWith(".OBML16") || s.ToUpper().EndsWith(".OGNC") || s.ToUpper().EndsWith(".OLP") || s.ToUpper().EndsWith(".OPML") || s.ToUpper().EndsWith(".OTH") || s.ToUpper().EndsWith(".P12") || s.ToUpper().EndsWith(".P7") || s.ToUpper().EndsWith(".P7B") || s.ToUpper().EndsWith(".P7C") || s.ToUpper().EndsWith(".PAC") || s.ToUpper().EndsWith(".PAGE") || s.ToUpper().EndsWith(".PEM") || s.ToUpper().EndsWith(".PHP") || s.ToUpper().EndsWith(".PHP2") || s.ToUpper().EndsWith(".PHP3") || s.ToUpper().EndsWith(".PHP4") || s.ToUpper().EndsWith(".PHP5") || s.ToUpper().EndsWith(".PHTM") || s.ToUpper().EndsWith(".PHTML") || s.ToUpper().EndsWith(".PPTHTML") || s.ToUpper().EndsWith(".PPTMHTML") || s.ToUpper().EndsWith(".PRF") || s.ToUpper().EndsWith(".PRO") || s.ToUpper().EndsWith(".PSP") || s.ToUpper().EndsWith(".PTW") || s.ToUpper().EndsWith(".PUB") || s.ToUpper().EndsWith(".QBO") || s.ToUpper().EndsWith(".QBX") || s.ToUpper().EndsWith(".QF") || s.ToUpper().EndsWith(".QRM") || s.ToUpper().EndsWith(".RFLW") || s.ToUpper().EndsWith(".RHTML") || s.ToUpper().EndsWith(".RJS") || s.ToUpper().EndsWith(".RSS") || s.ToUpper().EndsWith(".RT") || s.ToUpper().EndsWith(".RW3") || s.ToUpper().EndsWith(".RWP") || s.ToUpper().EndsWith(".RWSW") || s.ToUpper().EndsWith(".RWTHEME") || s.ToUpper().EndsWith(".SASS") || s.ToUpper().EndsWith(".SAVEDDECK") || s.ToUpper().EndsWith(".SCSS") || s.ToUpper().EndsWith(".SDB") || s.ToUpper().EndsWith(".SEAM") || s.ToUpper().EndsWith(".SHT") || s.ToUpper().EndsWith(".SHTM") || s.ToUpper().EndsWith(".SHTML") || s.ToUpper().EndsWith(".SITE") || s.ToUpper().EndsWith(".SITEMAP") || s.ToUpper().EndsWith(".SITES") || s.ToUpper().EndsWith(".SITES2") || s.ToUpper().EndsWith(".SPARKLE") || s.ToUpper().EndsWith(".SPC") || s.ToUpper().EndsWith(".SRF") || s.ToUpper().EndsWith(".SSP") || s.ToUpper().EndsWith(".STC") || s.ToUpper().EndsWith(".STL") || s.ToUpper().EndsWith(".STM") || s.ToUpper().EndsWith(".STML") || s.ToUpper().EndsWith(".STP") || s.ToUpper().EndsWith(".STRM") || s.ToUpper().EndsWith(".SUCK") || s.ToUpper().EndsWith(".SVC") || s.ToUpper().EndsWith(".SVR") || s.ToUpper().EndsWith(".SWZ") || s.ToUpper().EndsWith(".TPL") || s.ToUpper().EndsWith(".TVPI") || s.ToUpper().EndsWith(".TVVI") || s.ToUpper().EndsWith(".UCF") || s.ToUpper().EndsWith(".UHTML") || s.ToUpper().EndsWith(".URL") || s.ToUpper().EndsWith(".VBD") || s.ToUpper().EndsWith(".VBHTML") || s.ToUpper().EndsWith(".VDW") || s.ToUpper().EndsWith(".VLP") || s.ToUpper().EndsWith(".VRML") || s.ToUpper().EndsWith(".VRT") || s.ToUpper().EndsWith(".VSDISCO") || s.ToUpper().EndsWith(".WBS") || s.ToUpper().EndsWith(".WBXML") || s.ToUpper().EndsWith(".WDGT") || s.ToUpper().EndsWith(".WEB") || s.ToUpper().EndsWith(".WEBARCHIVE") || s.ToUpper().EndsWith(".WEBARCHIVEXML") || s.ToUpper().EndsWith(".WEBBOOKMARK") || s.ToUpper().EndsWith(".WEBHISTORY") || s.ToUpper().EndsWith(".WEBLOC") || s.ToUpper().EndsWith(".WEBSITE") || s.ToUpper().EndsWith(".WGP") || s.ToUpper().EndsWith(".WGT") || s.ToUpper().EndsWith(".WHTT") || s.ToUpper().EndsWith(".WIDGET") || s.ToUpper().EndsWith(".WML") || s.ToUpper().EndsWith(".WN") || s.ToUpper().EndsWith(".WOA") || s.ToUpper().EndsWith(".WPP") || s.ToUpper().EndsWith(".WPX") || s.ToUpper().EndsWith(".WRF") || s.ToUpper().EndsWith(".WSDL") || s.ToUpper().EndsWith(".XBEL") || s.ToUpper().EndsWith(".XBL") || s.ToUpper().EndsWith(".XFDL") || s.ToUpper().EndsWith(".XHT") || s.ToUpper().EndsWith(".XHTM") || s.ToUpper().EndsWith(".XHTML") || s.ToUpper().EndsWith(".XPD") || s.ToUpper().EndsWith(".XSS") || s.ToUpper().EndsWith(".XUL") || s.ToUpper().EndsWith(".XWS") || s.ToUpper().EndsWith(".ZFO") || s.ToUpper().EndsWith(".ZHTML") || s.ToUpper().EndsWith(".ZHTML") || s.ToUpper().EndsWith(".ZUL") || s.ToUpper().EndsWith(".ZVZ"))
                    {
                        Console.WriteLine("wtf? " + s);
                        alreadyFound.Add(s);
                    }
                    
                }

                return alreadyFound;
            }
            catch (Exception) { return new List<string>(); }

        }

        public static List<string> GetAllAccessibleFiles(string rootPath, List<string> alreadyFound = null)
        {
            try
            {
                if (alreadyFound == null)
                    alreadyFound = new List<string>();
                DirectoryInfo di = new DirectoryInfo(rootPath);
                var dirs = di.EnumerateDirectories();
                foreach (DirectoryInfo dir in dirs)
                {
                    if (!((dir.Attributes & FileAttributes.Hidden) == FileAttributes.Hidden))
                    {
                        alreadyFound = GetAllAccessibleFiles(dir.FullName, alreadyFound);
                    }
                }

                var files = Directory.GetFiles(rootPath);
                foreach (string s in files)
                {
                    alreadyFound.Add(s);
                }

                return alreadyFound;
            }
            catch (Exception) { return alreadyFound; }
           
        }

        static void Main(string[] args)
        {

            Console.WriteLine("--- Begin ---");

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



            //findLiveWebFiles();
            Console.WriteLine("Done");
            Console.ReadLine();
        }
    }
}
