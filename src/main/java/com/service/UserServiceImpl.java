package com.service;

import javax.transaction.Transactional;

import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import com.model.Role;
import com.model.User;
import com.repo.RoleRepo;
import com.repo.UserRepo;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;

@Slf4j
@RequiredArgsConstructor
@Service
@Transactional
public class UserServiceImpl implements UserService{

	private final UserRepo userRepo;
	private final RoleRepo roleRepo;
	private final PasswordEncoder passwordEncoder;
	
	@Override
	public User saveUser(User user) {
		log.info("Saving new user {} to database",user.getUsername());
		user.setPassword(passwordEncoder.encode(user.getPassword()));
		return userRepo.save(user);
	}

	@Override
	public Role saveRole(Role role) {
		log.info("Saving role {} to user",role.getName());
		return roleRepo.save(role);
	}

	@Override
	public void saveRoleToUser(String username, String roleName) {
		log.info("Adding role {} to user {}"+roleName,username);
		User user=userRepo.findByUsername(username);
		Role role=roleRepo.findByName(roleName);
		System.out.println(roleName+" "+username);
		user.getRoles().add(role);
		System.out.println(roleName+" "+username);
	}

}
