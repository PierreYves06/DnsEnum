fd=open('dic/test.txt', 'r')
n=0
for line in fd:
    n+=1
fd.close()
print(n)
l=round(n/2)
print(l)
fd1=open('dic/dic1', 'w')
fd2=open('dic/dic2', 'w')
fd3=open('dic/test.txt', 'r')
i=1
for line in fd3:
    print(line)
    if (i < l):
        print('fd1')
        fd1.write(line)
    else:
        print('fd2')
        fd2.write(line)
    i+=1
