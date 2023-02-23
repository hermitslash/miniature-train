package trmio.inc.els;

import io.quarkus.security.ForbiddenException;
import io.quarkus.security.identity.SecurityIdentity;
import io.smallrye.mutiny.Uni;
import org.jboss.logging.Logger;

import javax.inject.Inject;
import javax.security.auth.AuthPermission;
import javax.ws.rs.GET;
import javax.ws.rs.Path;
import javax.ws.rs.Produces;
import javax.ws.rs.core.MediaType;
import java.security.Permission;
import java.util.List;

@Path("/api/protected")
public class ProtectedResource {
    private final Logger logger = Logger.getLogger(ProtectedResource.class);
    @Inject
    SecurityIdentity identity;


    @GET
    @Produces(MediaType.APPLICATION_JSON)
    public Uni<List<Permission>> get() {
        logger.info(identity.getAttributes().toString());
        return identity.checkPermission(new AuthPermission("Confidential Resource")).onItem()
                .transform(granted -> {
                    logger.info(granted.toString());
                    if (granted) {
                        return identity.getAttribute("permissions");
                    }
                    throw new ForbiddenException();
                });
    }
}