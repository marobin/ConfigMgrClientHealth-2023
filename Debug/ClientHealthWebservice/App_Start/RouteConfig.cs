// Decompiled with JetBrains decompiler
// Type: ClientHealthWebservice.RouteConfig
// Assembly: ClientHealthWebservice, Version=1.0.0.0, Culture=neutral, PublicKeyToken=null
// MVID: 3BFC8FB3-876C-406B-9DDF-70D45BEA9D7D
// Assembly location: E:\_GITHUB\ConfigMgrClientHealth-bis\sources\ConfigMgr Client Health Webservice 2.0.1\bin\ClientHealthWebservice.dll

using System.Web.Mvc;
using System.Web.Routing;

namespace ClientHealthWebservice
{
  public class RouteConfig
  {
    public static void RegisterRoutes(RouteCollection routes)
    {
      routes.IgnoreRoute("{resource}.axd/{*pathInfo}");
      routes.MapRoute("Default", "{controller}/{action}/{id}", (object) new
      {
        controller = "Home",
        action = "Index",
        id = UrlParameter.Optional
      });
    }
  }
}
