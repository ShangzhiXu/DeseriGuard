## New GCs Found by Flash

### Basic

- dependency : jdk8u20

### Modify writeObject process built-in JDK

We find more `writeObject`  method that may lead to exploitation unsuccessful and we use Dynamic Agent to modify the behavior. We also provide the jar file in resources, the usage is like `-javaagent:src/main/resources/agent/xxx.jar` added in the vm option. Here are their functionality ：

- certPath.jar: remove `writeReplace`
- namedNode.jar: directly write fields
- jComponent_equals.jar: triger `equals` easily
- action_equals.jar: triger `equals` easily
- actionMap_equals.jar: triger `equals` easily
- css.jar: trigger `hashCode` easily
- actionMap_hashCode.jar: trigger `hashCode` easily
- jComponent_hashCode.jar: trigger `hashCode` easily
- basicPerms.jar: trigger `interface call` easily

## Known Gadget Chains

Our known gadget chains are based on two well-known projects, [ysoserial](https://github.com/frohoff/ysoserial) and [marshalsec](https://github.com/mbechler/marshalsec). Please refer to these projects for more information.
