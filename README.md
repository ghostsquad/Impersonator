Impersonator
============

C# class for impersonating another user

#Usage

```c#
using (new Impersonator(@"LAB\TestUser", "pass123"))
{
    //your impersonated code here
}
```
