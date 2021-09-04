using System;
using System.Text;
using Cosmos.Security.Verification;
using Cosmos.Text;

// ReSharper disable InconsistentNaming

namespace Cosmos.Validation
{
    public static class VerifyELF64Extensions
    {
        public static IPredicateValueRuleBuilder VerifyELF64(this IValueRuleBuilder builder, string hexVal, IgnoreCase ignoreCase = IgnoreCase.FALSE)
        {
            return builder.VerifyELF64(hexVal, Encoding.UTF8, ignoreCase);
        }

        public static IPredicateValueRuleBuilder VerifyELF64(this IValueRuleBuilder builder, string hexVal, Encoding encoding, IgnoreCase ignoreCase = IgnoreCase.FALSE)
        {
            if (builder is null)
                throw new ArgumentNullException(nameof(builder));
            return builder.Func(Elf64Handler.Verify()(hexVal)(encoding)(ignoreCase));
        }

        public static IPredicateValueRuleBuilder VerifyELF64(this IValueRuleBuilder builder, Func<IHashValue, bool> checker)
        {
            return builder.VerifyELF64(checker, Encoding.UTF8);
        }

        public static IPredicateValueRuleBuilder VerifyELF64(this IValueRuleBuilder builder, Func<IHashValue, bool> checker, Encoding encoding)
        {
            if (builder is null)
                throw new ArgumentNullException(nameof(builder));

            if (checker is null)
                throw new ArgumentNullException(nameof(checker));

            return builder.Func(Elf64Handler.CustomVerify()(encoding)(checker));
        }
        
        public static IPredicateValueRuleBuilder<T> VerifyELF64<T>(this IValueRuleBuilder<T> builder, string hexVal, IgnoreCase ignoreCase = IgnoreCase.FALSE)
        {
            return builder.VerifyELF64<T>(hexVal, Encoding.UTF8, ignoreCase);
        }

        public static IPredicateValueRuleBuilder<T> VerifyELF64<T>(this IValueRuleBuilder<T> builder, string hexVal, Encoding encoding, IgnoreCase ignoreCase = IgnoreCase.FALSE)
        {
            if (builder is null)
                throw new ArgumentNullException(nameof(builder));
            return builder.Func(Elf64Handler.Verify()(hexVal)(encoding)(ignoreCase));
        }

        public static IPredicateValueRuleBuilder<T> VerifyELF64<T>(this IValueRuleBuilder<T> builder, Func<IHashValue, bool> checker)
        {
            return builder.VerifyELF64<T>(checker, Encoding.UTF8);
        }

        public static IPredicateValueRuleBuilder<T> VerifyELF64<T>(this IValueRuleBuilder<T> builder, Func<IHashValue, bool> checker, Encoding encoding)
        {
            if (builder is null)
                throw new ArgumentNullException(nameof(builder));

            if (checker is null)
                throw new ArgumentNullException(nameof(checker));

            return builder.Func(Elf64Handler.CustomVerify()(encoding)(checker));
        }
        
        public static IPredicateValueRuleBuilder<T, TVal> VerifyELF64<T, TVal>(this IValueRuleBuilder<T, TVal> builder, string hexVal, IgnoreCase ignoreCase = IgnoreCase.FALSE)
        {
            return builder.VerifyELF64<T, TVal>(hexVal, Encoding.UTF8, ignoreCase);
        }

        public static IPredicateValueRuleBuilder<T, TVal> VerifyELF64<T, TVal>(this IValueRuleBuilder<T, TVal> builder, string hexVal, Encoding encoding, IgnoreCase ignoreCase = IgnoreCase.FALSE)
        {
            if (builder is null)
                throw new ArgumentNullException(nameof(builder));
            return builder.Func(Elf64Handler.Verify<TVal>()(hexVal)(encoding)(ignoreCase));
        }

        public static IPredicateValueRuleBuilder<T, TVal> VerifyELF64<T, TVal>(this IValueRuleBuilder<T, TVal> builder, Func<IHashValue, bool> checker)
        {
            return builder.VerifyELF64<T, TVal>(checker, Encoding.UTF8);
        }

        public static IPredicateValueRuleBuilder<T, TVal> VerifyELF64<T, TVal>(this IValueRuleBuilder<T, TVal> builder, Func<IHashValue, bool> checker, Encoding encoding)
        {
            if (builder is null)
                throw new ArgumentNullException(nameof(builder));

            if (checker is null)
                throw new ArgumentNullException(nameof(checker));

            return builder.Func(Elf64Handler.CustomVerify<TVal>()(encoding)(checker));
        }
    }
}