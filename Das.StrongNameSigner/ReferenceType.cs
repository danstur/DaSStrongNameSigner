using System;

namespace DaS.StrongNameSigner
{
    [Flags]
    internal enum ReferenceType
    {
        None = 0,
        CopyLocal = 1 << 0,
        Normal = 1 << 1
    }
}
