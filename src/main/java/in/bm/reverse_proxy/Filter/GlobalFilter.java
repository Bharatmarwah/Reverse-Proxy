package in.bm.reverse_proxy.Filter;

import in.bm.reverse_proxy.Token.JwtToken;
import org.springframework.cloud.gateway.filter.GatewayFilterChain;
import org.springframework.core.Ordered;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.stereotype.Component;
import org.springframework.web.server.ServerWebExchange;
import reactor.core.publisher.Mono;

@Component
public class GlobalFilter implements org.springframework.cloud.gateway.filter.GlobalFilter, Ordered {

    private final JwtToken jwtToken;

    public GlobalFilter(JwtToken jwtToken){
        this.jwtToken=jwtToken;
    }
    @Override
    public Mono<Void> filter(ServerWebExchange exchange, GatewayFilterChain chain) {
        String path = exchange.getRequest().getURI().getPath();
        if (publicPath(path)){
            return chain.filter(exchange);
        }
        String authHeader = exchange.getRequest().getHeaders().getFirst(HttpHeaders.AUTHORIZATION);
        if (authHeader==null||!authHeader.startsWith("Bearer ")){
            exchange.getResponse().setStatusCode(HttpStatus.UNAUTHORIZED);
            return exchange.getResponse().setComplete();
        }
        String token = authHeader.substring(7).trim();
        if(!jwtToken.validateToken(token)){
            exchange.getResponse().setStatusCode(HttpStatus.UNAUTHORIZED);
            return exchange.getResponse().setComplete();
        }
        String role = jwtToken.extractRole(token);
        if(path.startsWith("/admin")&&!role.equals("ADMIN")){
            exchange.getResponse().setStatusCode(HttpStatus.FORBIDDEN);
            return exchange.getResponse().setComplete();
        }

        if(path.startsWith("/user")&&!(role.equals("USER")||role.equals("ADMIN"))){
            exchange.getResponse().setStatusCode(HttpStatus.FORBIDDEN);
            return exchange.getResponse().setComplete();
        }

        return chain.filter(exchange);
    }
    private Boolean publicPath(String path){
        return path.startsWith("/user/login") || path.startsWith("/user/register");// Allow accessible APIs
    }
    @Override
    public int getOrder() {
        return 0;
    }
}
