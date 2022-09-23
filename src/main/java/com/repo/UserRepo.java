package com.repo;

import org.springframework.data.jpa.repository.JpaRepository;

import com.model.User;

public interface UserRepo extends JpaRepository<User, Long>{

	User findByUsername(String username);
}
