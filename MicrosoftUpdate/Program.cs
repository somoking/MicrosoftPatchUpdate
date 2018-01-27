using System;
using System.Net.Http.Headers;
using System.Text;
using System.Net.Http;
using System.Web;
using System.Threading.Tasks;
using System.IO;
using Newtonsoft.Json;
using Newtonsoft.Json.Linq;
using System.Collections.Generic;
using System.Linq;
using System.Text.RegularExpressions;
using System.Data.Entity;
using System.Collections;
using System.Globalization;

namespace MicrosoftUpdate
{
    class Program
    {
        static void Main(string[] args)
        {
           
            Task<string> task = MakeRequest();
            
            task.Wait();

            JObject NVDdatabase = JObject.Parse(task.Result);

            Dictionary<string, string> ProductNameLibrary = ProductMapper((JArray)NVDdatabase["ProductTree"]["FullProductName"]);

            List<PatchDetail> PatchRecords = new List<PatchDetail>();

            //Populated During Parse to match Patchs with there affected Products
            Dictionary<string, List<string>> PatchToProductMap = new Dictionary<string, List<string>>();

            //Parses through each CVE
            JArray Vulnerabilities = (JArray)NVDdatabase["Vulnerability"];
            foreach (JToken Vulnerability in Vulnerabilities)
            {
                //Parses through each PatchID
                JArray RemediationArray = (JArray)Vulnerability["Remediations"];
                foreach (JObject Remediation in RemediationArray)
                {
                    string PatchId = (string)Remediation["Description"]["Value"];
                    int Throw;//To be discarded Update with Regex 
                    bool result = Int32.TryParse(PatchId, out Throw);
                    // Build Patch to Product ID match
                    if (result)
                    {
                        if (PatchToProductMap.Keys.Contains(PatchId) != true)
                        {
                            PatchToProductMap.Add(PatchId, new List<string>());
                        }

                        foreach (JToken ProductID in Remediation["ProductID"])
                        {
                            if (PatchToProductMap[PatchId].Contains((string)ProductID)) { continue; }
                            PatchToProductMap[PatchId].Add((string)ProductID);
                        }
                    }
                }
                foreach (JObject Remediation in RemediationArray)
                {
                    string PatchId = (string)Remediation["Description"]["Value"];
                    if (PatchToProductMap.Keys.Contains(PatchId))
                    {

                        if(PatchRecords.Where(x => x.PatchNo == PatchId).Count() == 0)
                        {
                            List<string> ProductIDAssociation = PatchToProductMap[PatchId];
                            PatchDetail PatchRecord = new PatchDetail();

                            // Patch
                            PatchRecord.PatchNo = PatchId;
                            PatchRecord.PatchVersion = null;
                            PatchRecord.UpdateDateTime = DateTime.Now;
                            PatchRecord.UpdatedBy = "MicrsoftUpdateAPi";
                            PatchRecord.AppID = 1;
                            PatchRecord.TypeID = 1;
                            PatchRecord.DeployedOn = null;
                            PatchRecord.CreatedBy = "MicrsoftUpdateAPi";
                            PatchRecord.CreatedDateTime = DateTime.Now;
                            PatchRecord.Link = @"https://support.microsoft.com/en-us/help/" + PatchId;
                            PatchRecord.Title = (string)Vulnerability["Title"]["Value"];
                            PatchRecord.CVE = (string)Vulnerability["CVE"];


                            // Severity Levels
                            JArray ThreatArray = (JArray)Vulnerability["Threats"];
                            List<string> SeverityList = new List<string>();
                            foreach (JToken Threat in ThreatArray)
                            {

                                if ((int)Threat["Type"] == 3)// Alternative Types avalible Look at source material
                                {

                                    foreach (JToken ProductID in Threat["ProductID"])
                                    {
                                        if (ProductIDAssociation.Contains((string)ProductID))
                                        {
                                            SeverityList.Add((string)Threat["Description"]["Value"]);
                                        }
                                    }


                                }

                            }
                            PatchRecord.Severity = string.Join(" : ", SeverityList.Distinct());

                            // Pub Date
                            var RevisonArray = Vulnerability["RevisionHistory"];

                            foreach (JToken Revison in RevisonArray)
                            {
                                
                                    if ((string)Revison["Number"] == "1.0")
                                    {
                                        PatchRecord.Pubdate = Convert.ToDateTime((string)Revison["Date"]);
                                    }
                                    if ((string)Revison["Description"]["Value"] == "Information published.")
                                    {
                                        PatchRecord.Pubdate = Convert.ToDateTime((string)Revison["Date"]);
                                    }
                                

                            }

                            //Description
                            var NotesArray = Vulnerability["Notes"];

                            foreach (JToken Note in NotesArray)
                            {
                                if ((string)Note["Title"] == "Description")
                                {
                                    PatchRecord.Description = (string)Note["Value"];
                                }
                            }
                            //Populat Products Affected and Description List
                            List<string> ProductsAffected = new List<string>();

                            foreach (string product in ProductIDAssociation)
                            {
                                ProductsAffected.Add(ProductNameLibrary[product]);
                            }
                            PatchRecord.productsAffected = string.Join(",  ", ProductsAffected);


                            string Description = "<p> Effected versions <ul>";
                            foreach (string product in ProductsAffected)
                            {
                                Description += "<li>" + product + "</li>";
                            }
                            Description += "</ul></p>";
                            PatchRecord.Description += Description;



                            PatchRecords.Add(PatchRecord);

                        }

                    }

                }
            }
            Console.WriteLine("Data Population Complete");
            foreach (PatchDetail PatchRecord in PatchRecords)
            {
                if (PatchRecord.Link.Count() > 999) { Console.WriteLine("char Length error at " + PatchRecord.PatchNo + ":" + PatchRecord.Link); }
                if (PatchRecord.PatchNo.Count() > 500) { Console.WriteLine("char Length error at " + PatchRecord.PatchNo + ":" + PatchRecord.PatchNo); }
                if (PatchRecord.CVE.Count() > 250) { Console.WriteLine("char Length error at " + PatchRecord.PatchNo + ":" + PatchRecord.CVE); }
                if (PatchRecord.Title.Count() > 500) { Console.WriteLine("char Length error at " + PatchRecord.PatchNo  +":"+  PatchRecord.Title); }
                if (PatchRecord.Severity.Count() > 50) { Console.WriteLine("char Length error at " + PatchRecord.PatchNo + ":" + PatchRecord.Severity); }
                if (PatchRecord.productsAffected.Count() > 2000) { Console.WriteLine("char Length error at " + PatchRecord.PatchNo +":"+ PatchRecord.productsAffected); }
            }
                Console.WriteLine("Data to PatchDetails Start");
            //
            using (var dbCtx = new PatchMgrDevEntities())
            {

                int skipped = 0;
                foreach (PatchDetail PatchRecord in PatchRecords)
                {
                    
                    if (dbCtx.PatchDetails.Any(x => x.PatchNo == PatchRecord.PatchNo)) { skipped++;Console.WriteLine(skipped.ToString()); Console.WriteLine("skip "+PatchRecord.PatchNo); continue; }
                    dbCtx.PatchDetails.Add(PatchRecord);
                }
                  //  dbCtx.SaveChanges();
                


                Console.WriteLine("Console End");


            }
        }
        static Dictionary<string,string> ProductMapper (JArray ProductTree)
        {
            Dictionary<string, string> ProductIDDict = new Dictionary<string, string>();
            foreach (JObject Product in ProductTree)
            {
                ProductIDDict.Add((string)Product["ProductID"], (string)Product["Value"]);
            }
            return ProductIDDict;
        }
        static async Task<string> MakeRequest()
        {
            var client = new HttpClient();
            var queryString = HttpUtility.ParseQueryString(string.Empty);
            queryString["api-version"] = "2016-01-01";
            // Request headers
            client.DefaultRequestHeaders.Add("api-key", "");
            client.DefaultRequestHeaders.Accept.Add(new MediaTypeWithQualityHeaderValue("application/json"));
            //- Test if new Cvrf is avalible
            var Date = DateTime.Now;

            string month = Date.ToString("MMM", CultureInfo.InvariantCulture);//DateTime.Now.ToString("MMM", CultureInfo.InvariantCulture);
            int year = Date.Year;
            string APIdate = "'" + year.ToString() + "-" + month + "'";

            var uri = "https://api.msrc.microsoft.com/Updates(" + APIdate + ")?" + queryString;
            var ResponseCode = await client.GetAsync(uri);
            bool UpdateCheck = ResponseCode.IsSuccessStatusCode;
            while(UpdateCheck==false)
            {
                Date = Date.AddMonths(-1);
                month = Date.ToString("MMM", CultureInfo.InvariantCulture);
                APIdate = "'" + year.ToString() + "-" + month + "'";
                uri = "https://api.msrc.microsoft.com/Updates(" + APIdate + ")?" + queryString;
                ResponseCode = await client.GetAsync(uri);
                UpdateCheck = ResponseCode.IsSuccessStatusCode;
            }

            var UpdateResponse =JObject.Parse(ResponseCode.Content.ReadAsStringAsync().Result);
            uri = (string)UpdateResponse["value"][0]["CvrfUrl"];
            var response = await client.GetAsync(uri);

            Task<string> ApiResponse = response.Content.ReadAsStringAsync();
            return ApiResponse.Result;

        }
    }
}
