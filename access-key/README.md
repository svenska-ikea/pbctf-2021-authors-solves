# Access\_key (1 solve)

*I made a kernel driver that only allows me to get root access. Well......because only I have the key.*

## Description

This challenge consists of a int overflow that triggers a race condition based on kmalloc's behaviour. The challenge involves heap spraying to gain control of the object, subsequently leak, and Ret\_to\_CFU to obtain a root shell. The source code for this challenge was made public after 24 hours with no solves during the CTF.

## Driver Functionality

The object structure:

```C
struct object {
        unsigned long val1;
        struct object * next;
        unsigned long val2;
        unsigned int magic;
};
```

The IOCTL provides 4 options:

1. Create Node - This creates an object , initializes its magic with a random value, and adds it to the linked list of objects. Increments a reference count var.

2. Delete Node - Deletes the object. Instead of actually kfree()-ing the memory, it zeroes out the object and adds it to a single-linked list of "to be deleted" objects. Decrements the reference count var.

3. Overwrite - This call allows you write the secret\_value and the kernel .text address at a certain offset behind the object itself IF `object->val2` is non-zero.

4. The Access Function - Having the secret key and calling this function with it gives you RIP Control. It is the backdoor that this kernel driver has.


## Bugs

When the reference count hits 0, all the "to be deleted" objects are traversed and kfree()'ed. This is a general principle of how reference count variables are handled in kernel space. `cat System.map | grep ref | grep cnt` will reveal a ton of kernel reference count variables which have a garbage cleanup on hitting 0.

```C
if(!ref_cnt)
{
        kfree(ptr);
        kmalloc(128,GFP_KERNEL);
        ptr = NULL;
        while(freelist)
        {
                tmp = freelist;
                freelist = tmp->next;
                kfree(tmp);
        }
}
```

The bug is in the 4th line. `kmalloc(128,GFP_KERNEL)` CAN SLEEP. This comes from the man page of kmalloc:

`GFP_KERNEL - Allocate normal kernel ram. May sleep`.

`GFP_ATOMIC` is the flag for kmalloc that does not sleep.

So with the kernel actually being able to sleep, `ptr` gets kfree()-ed , but it does not get NULL-ed out. Another process can access the IOCTL interface of the driver and perform operations with a dangling `ptr`. This, in itself, isn't useful, because `ptr` is always NULL when unlinking happens in the main list. So it is effectively calling kfree(NULL).


The reference count variable is a global variable of type `unsigned char`. This is bad, because `char` can only hold 0x00-0xff. Creating 256 entries will set the reference count back to 0 instead of 256.

Combining these 2 bugs, we can actually make `ptr` non-zero when the garbage cleanup is trigerred. Create 257 objects and delete 1.

## Catching the object

It is important to now plan how we can control the contents of `ptr` and how useful it can be. Since we know that we can trigger the write of the `secret_value`, we must try to control `ptr->val2` , the offset. We can run a simple heap spray that should catch `ptr`'s freed memory, and control `val2`. Since this is a CTF Challenge, I wanted to make it easy , and made sure the most publicly available heap spraying technique - the msgsend() spray - can be used. With the `mtype` field of the msgsend() spray, you can control the value.

So, to make this work, we must

1. Run a heap spray.
2. Make kmalloc() sleep.
3. Trigger the overwrite from the IOCTL Interface BEFORE kmalloc() wakes up.

```C
printf("[*] Starting spray\n");
for(i=0; i<count; i++) {
	int msqid = msgget(IPC_PRIVATE, 0644 | IPC_CREAT);
	struct {
		long mtype;
		char mtext[10];
	} msg;

	memset(msg.mtext, 0x42, 10);
	msg.mtype = 0x2274f40;

	if(msgsnd(msqid, &msg, sizeof(msg.mtext), 0) < 0){
		perror("msgsnd");
	}
	ioctl(fd,0xcafeb003,10);
	// magic=10 because mtext is size 10.
}
```

To make kmalloc sleep, just

```C
for(i=0;i<1000;i++)
{
	for(j=0;j<256;j++)
		ioctl(fd,0xcafeb001,20);
	unsigned int lol = ioctl(fd,0xcafeb001,20);
	ioctl(fd,0xcafeb002,lol);
}
```

Run the 2 parallely, and you will gain control. For best results, let the spray run in background and during that, try to spam kmalloc(128, GFP_KERNEL).

## Where to Overwrite

With SMAP Enabled, we cannot just set the offset to a huge value that will make it point to userspace because it will trigger the SMAP violation. Also we don't know where the heap even is. At this point, there are couple ways to approach this. Find an object that is kmalloc()'d in the heap, and has data that will eventually be copied to userspace. Corrupt this data with `secret_value` and leak it.


## Physmap Spray

mmap 40k-50k pages with `MAP_POPULATE` flag in userspace. They will "appear" in the physmap area of the kernel address space. This is in the kernel heap itself, and since this is a "huge area", we can reliably have an overwrite from the IOCTL interface into the physmap area. Changes in physmap are reflected in userspace. So, in the event that we gain control of the chunk AND can trigger the IOCTL successfully, we need only search the mmap pages for a change in values. The change will be the leak.

```C
for(jk=0;jk<40000;jk++)
{
	for(by=1;by<(0x1000/8);by += 1)
	{
		if(*(arrr[jk] + by) != 0)
		{
			secret = *(arrr[jk] + by);
			leak = *(arrr[jk] + by + 1);
			leak = leak - 0x1caa50;
			race_flag = 2;
			printf("[+] secret: 0x%lx\n[+] kernel text: 0x%lx\n",secret,leak);
			break;
		}
	}
}
```

Thus I set `msg.mtype` to 0x2274f40 and I can reliably land in physmap. Now , we have the kernel text leak and the `secret_value`.

## The Backdoor

Now we have unlocked the 4th IOCTL Interface, and we can easily get RIP Control, however, with some constraints.

1. We can only call a function in kernel text, with no control over RDI,RSI or RDX.
2. The kernel crashes right after the function call.

So , if we must use the backdoor, we need to make sure we can "one-shot" to a root shell and not crash the kernel.

RSI is set to `ptr->magic` - a random value.

## Ret to CFU

Return to copy\_from\_user is a general technique to convert a function pointer exploit into a stack overflow. The idea is to jump to a copy\_from\_user call inside a kernel function , a few instructions behind it, where it loads RDI with a stack address and does not change RSI. Usually, RDX control is also required, and there are many targets to jump to , where the `RDI` is only changed right before the function call. For example:

```
   0xffffffff8102e422 <do_set_thread_area+18>:	mov    rsi,r13
   0xffffffff8102e425 <do_set_thread_area+21>:	push   rbx
   0xffffffff8102e426 <do_set_thread_area+22>:	mov    ebx,ecx
   0xffffffff8102e428 <do_set_thread_area+24>:	sub    rsp,0x10
   0xffffffff8102e42c <do_set_thread_area+28>:	mov    rdi,rsp <------- JUMP HERE
   0xffffffff8102e42f <do_set_thread_area+31>:	call   0xffffffff813d1b50 <_copy_from_user>
```

Since RSI is `ptr->magic` , a value we know, we can simply mmap a page at `magic` and store the payload there. The technique itself is very interesting, and useful in exploiting function pointers in network interfaces. Most of the times , RDI is always pointing to a `struct sock` , leaving us with only RSI and RDX control. However, in this situation, we dont control RDX yet.

If you look at the registers we control the moment RIP control happens, we see `rbx` set to 0x100. This is a nice value, and if we could somehow transfer this value into RDX, it would be perfect for an overflow. To find such an arrangement, you can check for xrefs to copy\_from\_user in IDA. There are around 652 xrefs in the current vmlinux. In about an hour of manual inspection of these gadgets, (5 seconds / xref), you will come across

```
   0xffffffff8125daf6 <oom_score_adj_write+22>:	lea    rdi,[rsp+0xb]
   0xffffffff8125dafb <oom_score_adj_write+27>:	mov    QWORD PTR [rsp+0xb],0x0
   0xffffffff8125db04 <oom_score_adj_write+36>:	mov    DWORD PTR [rsp+0x13],0x0
   0xffffffff8125db0c <oom_score_adj_write+44>:	mov    rdx,rbx
   0xffffffff8125db0f <oom_score_adj_write+47>:	mov    BYTE PTR [rsp+0x17],0x0
   0xffffffff8125db14 <oom_score_adj_write+52>:	call   0xffffffff813d1b50 <_copy_from_user>
```

Perfect.

## Escaping the function and hitting Epilogue

Since now we have smashed the kernel stack, we are however, still inside a kernel function called `oom_score_adj_write` , and we might crash the kernel if we continue on and wait for a function epilogue to be hit. Notice how every call to copy\_from\_user has error handling.

From the man page of copy\_from\_user, it copies one byte at a time, and on error, returns the number of bytes it failed to copy. When it fails, the function immediately returns. So in essence, if we can copy our payload and somehow make copy\_from\_user fail, we will immediately hit the function epilogue.

This is pretty easy - mmap 2 contiguous pages, munmap the 2nd page and make sure RSI+RDX lies in the 2nd page. Store payload near the end of the 1st page, and you will have full on stack control.

Do note that we can not have RDX larger than 0x150 , because that will hit the Stack Guard Page and crash the kernel. Since we have RDX set to 0x100 , we only need RSI at 0xXXXXX __F10__ or higher. This is because for mmap, minimum size of a page is PAGE\_SIZE , default to 4096 (0x1000) on x86\_64.
Since RSI is `ptr->magic`, which itself is random, we can simply wait till we get a magic value whose 3rd digit is 0xF.

```C
while(2>1)
	{
		xf = ioctl(fd,0xcafeb001,20);
		printf("[*] Got magic: 0x%lx\n",xf);
		if(( (xf / 0x100) % 0x10 == 0xf) && (xf / 0x10 ) % 0x10 < 0x5)
			break;
		else
			ioctl(fd,0xcafeb002,xf);
	}
```

## ROP

With SMEP and SMAP being pinned bits, we cannot just turn them off in CR4. A neat work-around this is to overwrite `poweroff_cmd` with our binary which will copy the flag to userspace and make it readable. Then call `orderly_poweroff(0)` followed by `msleep(0x100000)` and cat the flag in a different thread. To write to `poweroff_cmd` , you can use a `mov [rdi] , rsi` gadget.

## Conclusion

Final exploit combines all of the above and successfuly roots the kernel. The techniques described towards the end are themselves universally applicable to many kernel bugs with harsh constraints.

Congratulations to `valis` from `DragonSector` on solving this :)
