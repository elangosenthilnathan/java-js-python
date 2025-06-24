package io.shiftleft.controller;

import io.shiftleft.model.AuthToken;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.nio.charset.StandardCharsets;
import java.util.Base64;
import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import org.springframework.core.io.ClassPathResource;
import org.springframework.stereotype.Controller;
import org.springframework.util.FileCopyUtils;
import org.springframework.web.bind.annotation.CookieValue;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;


/**
 * Admin checks login
 */
@Controller
public class AdminController {
  private String fail = "redirect:/";

  // helper
  private boolean isAdmin(String auth)
// Authentication token model class for proper type safety
@Component
class AuthToken {
    private String role;
    
    public AuthToken() null
    
    public String getRole() {
        return role;
    }
    
    public void setRole(String role) {
        this.role = role;
    }
    
    public boolean isAdmin() {
        return "ADMIN".equals(role);
    }
}

// JWT configuration class
@Configuration
class JwtConfig {
    // Secret key extracted to configuration
    @Value("${jwt.secret:defaultSecretKeyWhichShouldBeChangedInProduction}")
    private String jwtSecret;
    
    @Bean
    public Key jwtSigningKey() {
        // Using a secure key generation method
        return Keys.hmacShaKeyFor(jwtSecret.getBytes());
    }
    
    @Bean
    public JwtParser jwtParser(Key jwtSigningKey) {
        return Jwts.parserBuilder()
                .setSigningKey(jwtSigningKey)
                .build();
    }
}

@Component
private boolean isAdmin(String jwtToken) {
    try {
        // Using JWT library instead of custom implementation
        Claims claims = jwtConfig.jwtParser().parseClaimsJws(jwtToken).getBody();
        
        // Validate token expiration
        Date expiration = claims.getExpiration();
        if (expiration != null && expiration.before(new Date())) {
            return false;
        }
        
        // Validate required claims and perform proper schema validation
        if (!claims.containsKey("role")) {
            return false;
        }
        
        // Type safety through strict role validation
        String role = claims.get("role", String.class);
        return "ADMIN".equals(role);
    } catch (JwtException ex) {
        // Secure exception handling without revealing details
        System.out.println("JWT validation error occurred");
        return false;
    } catch (Exception ex) {
        System.out.println("Authentication validation error occurred");
        return false;
    }
}

  //
  @RequestMapping(value = "/admin/printSecrets", method = RequestMethod.POST)
  public String doPostPrintSecrets(HttpServletResponse response, HttpServletRequest request) {
    return fail;
  }


  @RequestMapping(value = "/admin/printSecrets", method = RequestMethod.GET)
  public String doGetPrintSecrets(@CookieValue(value = "auth", defaultValue = "notset") String auth, HttpServletResponse response, HttpServletRequest request) throws Exception {

    if (request.getSession().getAttribute("auth") == null) {
      return fail;
    }

    String authToken = request.getSession().getAttribute("auth").toString();
    if(!isAdmin(authToken)) {
      return fail;
    }

    ClassPathResource cpr = new ClassPathResource("static/calculations.csv");
    try {
      byte[] bdata = FileCopyUtils.copyToByteArray(cpr.getInputStream());
      response.getOutputStream().println(new String(bdata, StandardCharsets.UTF_8));
      return null;
    } catch (IOException ex) {
      ex.printStackTrace();
      // redirect to /
      return fail;
    }
  }

  /**
   * Handle login attempt
   * @param auth cookie value base64 encoded
   * @param password hardcoded value
   * @param response -
   * @param request -
   * @return redirect to company numbers
   * @throws Exception
   */
  @RequestMapping(value = "/admin/login", method = RequestMethod.POST)
@Value("${jwt.expiration:3600000}") // 1 hour in milliseconds
private long jwtExpirationMs;

@Value("${jwt.issuer:ShiftLeftSecureApp}")
private String jwtIssuer;

@RequestMapping(value = "/admin/login", method = RequestMethod.POST)
public String doPostLogin(@CookieValue(value = "auth", defaultValue = "notset") String auth, 
                         @RequestBody String password, 
                         HttpServletResponse response, 
                         HttpServletRequest request) throws Exception {
    String succ = "redirect:/admin/printSecrets";

    try {
        // no cookie no fun
        if (!auth.equals("notset")) {
            if(isAdmin(auth)) {
                request.getSession().setAttribute("auth", auth);
                return succ;
            }
        }

        // split password=value
        String[] pass = password.split("=");
        if(pass.length!=2) {
            return fail;
        }
        
        // compare pass - consider using password hashing in production
        if(pass[1] != null && pass[1].length()>0 && pass[1].equals("shiftleftsecret"))
        {
            // Generate secure JWT token with proper claims and expiration
            Date now = new Date();
            Date expirationDate = new Date(now.getTime() + jwtExpirationMs);
            
            // Creating JWT with standard claims for better security
            String jwtToken = Jwts.builder()
                .claim("role", "ADMIN")
                .setIssuer(jwtIssuer)
                .setIssuedAt(now)
                .setExpiration(expirationDate)
                .setSubject("admin-user") // Consider using actual user ID in production
                .signWith(jwtConfig.jwtSigningKey())
                .compact();
            
            // Set secure cookie
            Cookie secureCookie = new Cookie("auth", jwtToken);
            secureCookie.setHttpOnly(true);  // Prevent JavaScript access
            secureCookie.setSecure(true);    // Send only over HTTPS
            secureCookie.setPath("/");       // Scope to application
            secureCookie.setMaxAge((int) (jwtExpirationMs / 1000)); // Convert ms to seconds
            response.addCookie(secureCookie);
            
            // Store in session
            request.getSession().setAttribute("auth", jwtToken);

            return succ;
        }
        return fail;
    }
    catch (Exception ex)
    {
        // Secure exception handling without revealing implementation details
        System.out.println("Login process error occurred");
        return fail;
    }
}

  /**
   * Same as POST but just a redirect
   * @param response
   * @param request
   * @return redirect
   */
  @RequestMapping(value = "/admin/login", method = RequestMethod.GET)
  public String doGetLogin(HttpServletResponse response, HttpServletRequest request) {
    return "redirect:/";
  }
}
