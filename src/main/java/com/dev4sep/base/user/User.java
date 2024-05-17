/**
 * Copyright 2024 DEV4Sep
 * <p>
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 * <p>
 * http://www.apache.org/licenses/LICENSE-2.0
 * <p>
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package com.dev4sep.base.user;

import com.dev4sep.base.role.Role;
import jakarta.persistence.*;
import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;
import lombok.experimental.SuperBuilder;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;

import java.security.Principal;
import java.time.LocalDateTime;
import java.util.Collection;
import java.util.Date;
import java.util.List;
import java.util.stream.Collectors;

/**
 * @author YISivlay
 */
@Getter
@Setter
@SuperBuilder
@NoArgsConstructor
@AllArgsConstructor
@Entity
@Table(name = "tbl_user")
public class User implements UserDetails, Principal {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @ManyToMany(fetch = FetchType.EAGER)
    private List<Role> roles;

    @Column(name = "username", unique = true, nullable = false)
    private String username;

    @Column(name = "password", unique = true, nullable = false)
    private String password;

    @Column(name = "firstname", length = 100)
    private String firstname;

    @Column(name = "lastname", length = 100)
    private String lastname;

    @Column(name = "email", length = 150)
    private String email;

    @Temporal(TemporalType.DATE)
    @Column(name = "dob")
    private Date dob;

    @Column(name = "gender")
    private String gender;

    @Column(name = "is_account_non_expired", nullable = false)
    private boolean isAccountNonExpired;

    @Column(name = "is_account_non_locked", nullable = false)
    private boolean isAccountNonLocked;

    @Column(name = "is_credentials_non_expired", nullable = false)
    private boolean isCredentialsNonExpired;

    @Column(name = "is_enabled", nullable = false)
    private boolean isEnabled;

    @Column(name = "createdby_id")
    private Long createdBy;

    @Temporal(TemporalType.TIMESTAMP)
    @Column(name = "created_date")
    private LocalDateTime createdDate;

    @Column(name = "lastmodifiedby_id")
    private Long lastModifiedBy;

    @Temporal(TemporalType.TIMESTAMP)
    @Column(name = "lastmodified_date")
    private LocalDateTime lastModifiedDate;

    @Override
    public String getName() {
        return this.firstname + " " + this.lastname;
    }

    @Override
    public Collection<? extends GrantedAuthority> getAuthorities() {
        return this.roles.stream()
                .map(role -> new SimpleGrantedAuthority(role.getName()))
                .collect(Collectors.toList());
    }

    @Override
    public String getPassword() {
        return this.password;
    }

    @Override
    public String getUsername() {
        return this.username;
    }

    @Override
    public boolean isAccountNonExpired() {
        return this.isAccountNonExpired;
    }

    @Override
    public boolean isAccountNonLocked() {
        return this.isAccountNonLocked;
    }

    @Override
    public boolean isCredentialsNonExpired() {
        return this.isCredentialsNonExpired;
    }

    @Override
    public boolean isEnabled() {
        return this.isEnabled;
    }
}
