using System;
using System.Collections.Generic;
using System.Configuration;
using System.Linq;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using System.Web;
using JWTClient;

namespace JWTModule
{
    //This module is used in authenticating API requests using JWT
    public class JWTModule : IHttpModule
    {
        public void Init(HttpApplication application)
        {
            application.BeginRequest +=
                (new EventHandler(this.Application_BeginRequest));
        }
        private void Application_BeginRequest(Object source,
         EventArgs e)
        {

            var request = HttpContext.Current.Request;

            //Module functionality
            var header = request.Headers.GetValues("Authorization");
            string filePath = request.FilePath;
            var nonAuthenticatedAPIs = ConfigurationManager.AppSettings["NonAuthenticatedAPIs"].Split(',');

            if (request.HttpMethod == "OPTIONS")
                return;
            if (((filePath.StartsWith("/api")) ||(filePath.StartsWith("/Account"))) && (!(nonAuthenticatedAPIs.Any(a => filePath.Contains(a)&&!String.IsNullOrEmpty(a)))))
            {

                if (header == null)
                {
                    HttpContext.Current.Response.StatusCode = 401;
                    return;
                }
                    
                var token = header.FirstOrDefault();
                if (String.IsNullOrEmpty(token))
                {
                    HttpContext.Current.Response.StatusCode = 401;
                }
                    



                var isValidToken = JWTClient.IsValidToken(token);
                if (!isValidToken)
                {
                    HttpContext.Current.Response.StatusCode = 401;
                }
                    
            }
            
        }
        
        public void Dispose() { }
    }
}
