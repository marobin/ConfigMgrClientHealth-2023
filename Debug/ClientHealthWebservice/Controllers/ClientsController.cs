// Decompiled with JetBrains decompiler
// Type: ClientHealthWebservice.Controllers.ClientsController
// Assembly: ClientHealthWebservice, Version=1.0.0.0, Culture=neutral, PublicKeyToken=null
// MVID: 3BFC8FB3-876C-406B-9DDF-70D45BEA9D7D
// Assembly location: E:\_GITHUB\ConfigMgrClientHealth-bis\sources\ConfigMgr Client Health Webservice 2.0.1\bin\ClientHealthWebservice.dll

using ClientHealthWebservice.Models;
using System;
using System.Configuration;
using System.Data.Entity;
using System.Data.Entity.Infrastructure;
using System.Linq;
using System.Linq.Expressions;
using System.Net;
using System.Web.Http;
using System.Web.Http.Description;

namespace ClientHealthWebservice.Controllers
{
  public class ClientsController : ApiController
  {
    private ClientDBContext db = new ClientDBContext(ConfigurationManager.ConnectionStrings["ConnectionString"].ConnectionString);

    [ResponseType(typeof (Client))]
    public IHttpActionResult GetClient(string id) => this.db.Clients.Find(new object[1]
    {
      (object) id
    }) == null ? (IHttpActionResult) this.NotFound() : (IHttpActionResult) this.StatusCode(HttpStatusCode.OK);

    [ResponseType(typeof (void))]
    public IHttpActionResult PutClient(string id, Client client)
    {
      if (!this.ModelState.IsValid)
        return (IHttpActionResult) this.BadRequest(this.ModelState);
      if (id != client.Hostname)
        return (IHttpActionResult) this.BadRequest();
      this.db.Entry<Client>(client).State = EntityState.Modified;
      try
      {
        this.db.SaveChanges();
      }
      catch (DbUpdateConcurrencyException ex)
      {
        if (!this.ClientExists(id))
          return (IHttpActionResult) this.NotFound();
        throw;
      }
      return (IHttpActionResult) this.StatusCode(HttpStatusCode.NoContent);
    }

    [ResponseType(typeof (Client))]
    public IHttpActionResult PostClient(Client client)
    {
      if (!this.ModelState.IsValid)
        return (IHttpActionResult) this.BadRequest(this.ModelState);
      this.db.Clients.Add(client);
      try
      {
        this.db.SaveChanges();
      }
      catch (DbUpdateException ex)
      {
        if (this.ClientExists(client.Hostname))
          return (IHttpActionResult) this.Conflict();
        throw;
      }
      return (IHttpActionResult) this.CreatedAtRoute<Client>("DefaultApi", (object) new
      {
        id = client.Hostname
      }, client);
    }

    protected override void Dispose(bool disposing)
    {
      if (disposing)
        this.db.Dispose();
      base.Dispose(disposing);
    }

    private bool ClientExists(string id) => this.db.Clients.Count<Client>((Expression<Func<Client, bool>>) (e => e.Hostname == id)) > 0;
  }
}
