package in.ac.charusat.studentmgmtsystem.repository;

import in.ac.charusat.studentmgmtsystem.model.User;
import org.springframework.data.jpa.repository.JpaRepository;

public interface UserRepository extends JpaRepository<User, Long> {
    User findByUsername(String username);
}