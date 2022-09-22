package in.ac.charusat.studentmgmtsystem;

import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Component;

import java.util.Date;

@Component
public class JwtUtils {

    private String jwtSecret = "parth1234";

    private int jwtExpirationMS= 86400000;

    public String generateJwtToken(Authentication authentication){
        UserDetails userDetails = (UserDetails) authentication.getPrincipal();
        return Jwts.builder().setSubject(userDetails.getUsername()).setIssuedAt(new Date()).setExpiration(new Date(new Date().getTime()+jwtExpirationMS)).signWith(SignatureAlgorithm.HS512, jwtSecret).compact();
    }

    public String getUserNameFromJwtToken(String token){
        return Jwts.parser().setSigningKey(jwtSecret).parseClaimsJws(token).getBody().getSubject();
    }

    public boolean validateJwtToken(String token){
        try{
            Jwts.parser().setSigningKey(jwtSecret).parseClaimsJws(token);
            return true;
        }catch(Exception e){
            System.out.println("Invalid token " + e);
        }
        return false;
    }
}