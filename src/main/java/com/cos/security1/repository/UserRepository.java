package com.cos.security1.repository;

import com.cos.security1.model.User;
import org.springframework.data.jpa.repository.JpaRepository;

// CRUD 함수를 JpaRepository가 들고 있음
// @Repository 어노테이션 없어도 IoC됨. JpaRepository 상속했기 때문에
public interface UserRepository extends JpaRepository<User, Integer> {
    //findByUsername JPA 쿼리 메소드
    public User findByUsername(String username); // select * from user where username = ?

    public User findByEmail(String email); // select * from user where email = ?
}
