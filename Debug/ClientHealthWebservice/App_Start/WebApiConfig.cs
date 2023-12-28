// Decompiled with JetBrains decompiler
// Type: ClientHealthWebservice.WebApiConfig
// Assembly: ClientHealthWebservice, Version=1.0.0.0, Culture=neutral, PublicKeyToken=null
// MVID: 3BFC8FB3-876C-406B-9DDF-70D45BEA9D7D
// Assembly location: E:\_GITHUB\ConfigMgrClientHealth-bis\sources\ConfigMgr Client Health Webservice 2.0.1\bin\ClientHealthWebservice.dll

using System.Web.Http;

namespace ClientHealthWebservice
{
  public static class WebApiConfig
  {
    public static void Register(HttpConfiguration config)
    {
      config.MapHttpAttributeRoutes();
      config.Routes.MapHttpRoute("DefaultApi", "{controller}/{id}", (object) new
      {
        id = RouteParameter.Optional
      });
    }
  }
}
