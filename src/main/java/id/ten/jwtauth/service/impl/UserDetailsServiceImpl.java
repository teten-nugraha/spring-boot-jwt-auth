package id.ten.jwtauth.service.impl;

import id.ten.jwtauth.model.User;
import id.ten.jwtauth.repository.UserRepository;
import id.ten.jwtauth.service.UserDetailsService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

import javax.transaction.Transactional;

/**
 * Class ini digunakan untuk mendapatkan username dari suatu database
 *
 * @version 0.0.1-SNAPSHOT
 * @author TetenNugraha
 * @since 03-06-2021
 */
@Service
public class UserDetailsServiceImpl implements UserDetailsService {

    @Autowired
    private UserRepository userRepository;


    @Override
    @Transactional
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        User user = userRepository.findByUsername(username)
                .orElseThrow(() -> new UsernameNotFoundException("User Not Found with username: " + username));

        return UserDetailsImpl.build(user);
    }
}
