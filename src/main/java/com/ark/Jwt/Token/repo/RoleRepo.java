
package com.ark.Jwt.Token.repo;

import com.ark.Jwt.Token.domain.Role;
import org.springframework.data.jpa.repository.JpaRepository;

public interface RoleRepo extends JpaRepository<Role, Long> {

    Role findByName(String name);
}