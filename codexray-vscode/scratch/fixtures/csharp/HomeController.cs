using System.Diagnostics;
using System.Data.SqlClient;
using Microsoft.AspNetCore.Mvc;

public class HomeController : Controller {
  private SqlConnection conn;

  [HttpGet]
  public IActionResult Run() {
    // UNDEFENDED: Request.Query into Process.Start
    var ip = Request.Query["ip"];
    Process.Start("ping " + ip);
    return Content("ok");
  }

  [HttpGet]
  public IActionResult User([FromQuery] string id) {
    // UNDEFENDED: concatenated SQL via SqlCommand ctor
    var cmd = new SqlCommand("SELECT * FROM u WHERE id = " + id, conn);
    cmd.ExecuteReader();
    return Content("ok");
  }

  [HttpGet]
  public IActionResult Guarded([FromQuery] string n) {
    // GUARDED: int.Parse neutralises before Process.Start
    var safe = int.Parse(n);
    Process.Start("sleep " + safe);
    return Content("ok");
  }
}
