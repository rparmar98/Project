package com.service;

import com.model.Role;
import com.model.User;

public interface UserService {

	User saveUser(User user);
	Role saveRole(Role role);
	public void saveRoleToUser(String username,String roleName);
}
