package com.lunatic.loginservice.repository;

import com.lunatic.loginservice.models.Role;
import org.springframework.data.jpa.repository.JpaRepository;

public interface RoleRepository extends JpaRepository<Role, String> {
}
