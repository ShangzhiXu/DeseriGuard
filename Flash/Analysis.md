### 目标
想找到CC3里面的第一条调用链
https://github.com/frohoff/ysoserial/blob/master/src/main/java/ysoserial/payloads/CommonsCollections1.java
```cpp
/*
	Gadget chain:
		ObjectInputStream.readObject()
			AnnotationInvocationHandler.readObject()
				Map(Proxy).entrySet()
					AnnotationInvocationHandler.invoke()
						LazyMap.get()
							ChainedTransformer.transform()
								ConstantTransformer.transform()
								InvokerTransformer.transform()
									Method.invoke()
										Class.getMethod()
								InvokerTransformer.transform()
									Method.invoke()
										Runtime.getRuntime()
								InvokerTransformer.transform()
									Method.invoke()
										Runtime.exec()

	Requires:
		commons-collections
 */
```

### 测试

1. 编译命令 `./gradlew clean installDist`
2. 分别用 ` -Xmx16G` 和 ` -Xmx8G` 都跑了一次，都跑不出来，所以应该不是内存的问题。
3. 我输出了一个图，就是gadget chain graph [gadget-graph.pdf](https://github.com/user-attachments/files/24613224/gadget-graph.pdf)

