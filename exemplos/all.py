a=1

b=func(a)

if(a):
	c=sanitize(b)
elif(a<2 and a!=0):
	c=taint(b)
elif(a>2 or not a):
	c=untaint(b)
elif(a==a):
	execute(b)

while(a):
	a=a-1

result= "final "+a+' output'