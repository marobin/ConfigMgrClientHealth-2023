// Decompiled with JetBrains decompiler
// Type: ClientHealthWebservice.WebApiApplication
// Assembly: ClientHealthWebservice, Version=1.0.0.0, Culture=neutral, PublicKeyToken=null
// MVID: 3BFC8FB3-876C-406B-9DDF-70D45BEA9D7D
// Assembly location: E:\_GITHUB\ConfigMgrClientHealth-bis\sources\ConfigMgr Client Health Webservice 2.0.1\bin\ClientHealthWebservice.dll

using System;
using System.Web;
using System.Web.Http;
using System.Web.Mvc;
using System.Web.Optimization;
using System.Web.Routing;

namespace ClientHealthWebservice
{
  public class WebApiApplication : HttpApplication
  {
    protected void Application_Start()
    {
      AreaRegistration.RegisterAllAreas();
      GlobalConfiguration.Configure(new Action<HttpConfiguration>(WebApiConfig.Register));
      FilterConfig.RegisterGlobalFilters(GlobalFilters.Filters);
      RouteConfig.RegisterRoutes(RouteTable.Routes);
      BundleConfig.RegisterBundles(BundleTable.Bundles);
    }
  }
}
