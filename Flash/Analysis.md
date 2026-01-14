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
3. 我输出了一个图，就是gadget chain graph [gadget-graph.pdf](https://github.com/user-attachments/files/24613224/gadget-graph.pdf)，可以看到其实他执行`backward from <java.lang.Runtime: java.lang.Process exec(java.lang.String)>`以及什么都没有扫到，只扫到了`openConnection()`相关的调用链
4. 从getGCs开始一步一步打断点看，他就是沿着图做了一个DFS
5. 搜的过程中我看到的是，从exec出发这步能追得到
   ```
   Method.invoke()
   ```
   再往上InvokerTransformer.transform就断掉了，考虑是不是对这个transform没有定义，在https://github.com/CGCL-codes/Flash/blob/main/java-benchmarks/JDV/priori-knowledge.yml里面
   但是添加上之后，也扫不出来，感觉是对于这种反射的处理还是不够好。
   

