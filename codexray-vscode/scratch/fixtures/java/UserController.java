import java.sql.*;
import org.springframework.web.bind.annotation.*;

@RestController
public class UserController {
  private Connection conn;

  @GetMapping("/run")
  public String run(@RequestParam String ip) throws Exception {
    // UNDEFENDED: tainted param straight into command exec
    Runtime.getRuntime().exec("ping " + ip);
    return ip;
  }

  @GetMapping("/user")
  public String user(@RequestParam String id) throws Exception {
    // UNDEFENDED: string-concatenated SQL
    Statement st = conn.createStatement();
    st.executeQuery("SELECT * FROM users WHERE id = " + id);
    return id;
  }

  @GetMapping("/guarded")
  public String guarded(@RequestParam String n) throws Exception {
    // GUARDED: parseInt neutralises before command exec
    int safe = Integer.parseInt(n);
    Runtime.getRuntime().exec("sleep " + safe);
    return "ok";
  }

  @GetMapping("/weak")
  public String weak(@RequestParam String q) throws Exception {
    // WEAK: html escape does not defend a SQL sink
    String e = org.springframework.web.util.HtmlUtils.htmlEscape(q);
    Statement st = conn.createStatement();
    st.executeQuery("SELECT * FROM t WHERE a = '" + e + "'");
    return "ok";
  }

  public String notReachable(String x) {
    return x.toUpperCase();
  }
}
