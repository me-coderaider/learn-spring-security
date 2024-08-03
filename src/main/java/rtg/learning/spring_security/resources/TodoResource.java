package rtg.learning.spring_security.resources;

import java.util.List;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.access.annotation.Secured;
import org.springframework.security.access.prepost.PostAuthorize;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RestController;

import jakarta.annotation.security.RolesAllowed;

@RestController
public class TodoResource {
	
	private Logger logger=LoggerFactory.getLogger(getClass());
	
	private static final List<Todo> TODOS_LIST = List.of(new Todo("coderaider","Learn to memorize"),new Todo("coderaider","Learn Microservices"));

	@GetMapping(path="/todos")
	public List<Todo> retrieveAllTodos() {
		return TODOS_LIST;
	}
	
	@GetMapping(path="/users/{username}/todos")
//	@PreAuthorize("hasRole('USER') and authentication.name==#username")
	@PostAuthorize("returnObject.username=='coderaider'")
	@RolesAllowed({"ADMIN","USER"})
	@Secured({"ROLE_ADMIN","ROLE_USER"})
	public Todo retrieveTodosForSpecificUser(@PathVariable("username") String username) {
		logger.info("Passed Username is {}", username);
		return TODOS_LIST.get(0);
	}
	
	@PostMapping(path="/users/{username}/todos")
	public void createTodosForSpecificUser(@PathVariable("username") String username, @RequestBody Todo todo) {
		logger.info("Create {} for {}", todo, username);
	}
}

record Todo(String username, String description) {}
