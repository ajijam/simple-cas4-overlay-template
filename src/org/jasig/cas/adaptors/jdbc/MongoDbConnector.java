/*
 * Licensed to Jasig under one or more contributor license
 * agreements. See the NOTICE file distributed with this work
 * for additional information regarding copyright ownership.
 * Jasig licenses this file to you under the Apache License,
 * Version 2.0 (the "License"); you may not use this file
 * except in compliance with the License.  You may obtain a
 * copy of the License at the following location:
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied.  See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */
package org.jasig.cas.adaptors.jdbc;

import java.security.GeneralSecurityException;

import org.jasig.cas.authentication.HandlerResult;
import org.jasig.cas.authentication.PreventedException;
import org.jasig.cas.authentication.UsernamePasswordCredential;
import org.jasig.cas.authentication.principal.SimplePrincipal;
import org.springframework.beans.factory.InitializingBean;
import org.springframework.dao.DataAccessException;
import org.springframework.data.authentication.UserCredentials;
import org.springframework.data.mongodb.core.MongoTemplate;

import com.mongodb.BasicDBObject;
import com.mongodb.DB;
import com.mongodb.DBCollection;
import com.mongodb.DBCursor;
import com.mongodb.DBObject;
import com.mongodb.Mongo;
import com.mongodb.MongoClient;

import javax.security.auth.login.FailedLoginException;
import javax.validation.constraints.NotNull;

/**
 * Class that given a table, username field and password field will query a
 * database table with the provided encryption technique to see if the user
 * exists. This class defaults to a PasswordTranslator of
 * PlainTextPasswordTranslator.
 *
 * @author Scott Battaglia
 * @author Dmitriy Kopylenko
 * @author Marvin S. Addison
 *
 * @since 3.0
 */

public class MongoDbConnector extends AbstractJdbcUsernamePasswordAuthenticationHandler implements InitializingBean {


    @NotNull
    private String fieldUser;

    @NotNull
    private String fieldPassword;

    @NotNull
    private String tableUsers;

    @NotNull
    private String username;



    /** {@inheritDoc} */
    @Override
    protected final HandlerResult authenticateUsernamePasswordInternal(final UsernamePasswordCredential credential)
            throws GeneralSecurityException, PreventedException {
        
        final String userName = credential.getUsername();
        
        final String encyptedPassword = getPasswordEncoder().encode(credential.getPassword());


        MongoClient mongoClient = new MongoClient("localhost", 27017);

        DB db = mongoClient.getDB("test");

        DBCollection coll = db.getCollection("user");
        
        // querying mongo db.
        
        BasicDBObject query=new BasicDBObject("userName",userName).append("passWord", encyptedPassword);
       
        DBCursor cursor= coll.find(query);
       
       try {
           while(cursor.hasNext()) {
       /*        System.out.println("cursor value"+cursor.next());*/
               return createHandlerResult(credential, this.principalFactory.createPrincipal(username), null);
           }
        } finally {
           cursor.close();
        }
  
        return null;

      
        // final int count;
        // try {
        // count = getJdbcTemplate().queryForObject(this.sql, Integer.class, username, encyptedPassword);
        // } catch (final DataAccessException e) {
        // throw new PreventedException("SQL exception while executing query for " + username, e);
        // }
        // if (count == 0) {
        // ;
        // }
        
    }

    @Override
    public void afterPropertiesSet() throws Exception {
    
        /*this.sql = SQL_PREFIX + this.tableUsers + " WHERE " + this.fieldUser + " = ? AND " + this.fieldPassword
                + " = ?";*/
    }

    /**
     * @param fieldPassword
     *            The fieldPassword to set.
     */
    public final void setFieldPassword(final String fieldPassword) {
        this.fieldPassword = fieldPassword;
    }

    /**
     * @param fieldUser
     *            The fieldUser to set.
     */
    public final void setFieldUser(final String fieldUser) {
        this.fieldUser = fieldUser;
    }

    /**
     * @param tableUsers
     *            The tableUsers to set.
     */
    public final void setTableUsers(final String tableUsers) {
        this.tableUsers = tableUsers;
    }
}