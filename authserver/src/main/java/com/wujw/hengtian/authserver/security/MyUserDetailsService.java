package com.wujw.hengtian.authserver.security;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.core.authority.AuthorityUtils;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;

import javax.sql.DataSource;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;


/**
 * Created by wujw on 17/3/28.
 */
public class MyUserDetailsService implements UserDetailsService {
    Logger log = LoggerFactory.getLogger(MyUserDetailsService.class);
    DataSource dataSource;
    public MyUserDetailsService(DataSource dataSource){
        this.dataSource=dataSource;
    }
    public static  final String SECLECTUSERBYUSERNAME=" select * from t_user where  username=?";
    public static  final String GETROLSBYUSERID=" select rolename from t_role r left join role_user ru " +
            "on r.id = ru.role_id " +
            "where  ru.user_id=?";

    @Override
    public UserDetails loadUserByUsername(String s) throws UsernameNotFoundException {
        String username;
        String name;
        String password;
        Long id;
        try {
            PreparedStatement ps = this.dataSource.getConnection().prepareStatement(SECLECTUSERBYUSERNAME);
            ps.setString(1,s);
            ResultSet rs = ps.executeQuery();
            if(rs.next()){
                id=rs.getLong("id");
                username = rs.getString("username" );
                name=rs.getString("name");
                password=rs.getString("password");
                PreparedStatement rolps = dataSource.getConnection().prepareStatement(GETROLSBYUSERID);
                rolps.setLong(1,id);
                ResultSet ro = rolps.executeQuery();
                ro.last();
                String[] roles = new String[ro.getRow()];
                int index=0;
                ro.beforeFirst();
                while(ro.next()){
                    String rolename=ro.getString("rolename");
                    roles[index]=rolename;
                    index++;
                }
                return new MyUser(name,username,password, AuthorityUtils.createAuthorityList(roles));
            }

        } catch (SQLException e) {
            e.printStackTrace();
        }



        return null;
    }
}
