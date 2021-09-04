using System;
using System.Text;
using Cosmos.Security.Verification;
using Cosmos.Text;

// ReSharper disable InconsistentNaming

namespace Cosmos.Validation
{
    public static class VerifySM3Extensions
    {
        public static IPredicateValueRuleBuilder VerifySM3(this IValueRuleBuilder builder, string hexVal, IgnoreCase ignoreCase = IgnoreCase.FALSE)
        {
            return builder.VerifySM3(hexVal, Encoding.UTF8, ignoreCase);
        }

        public static IPredicateValueRuleBuilder VerifySM3(this IValueRuleBuilder builder, string hexVal, Encoding encoding, IgnoreCase ignoreCase = IgnoreCase.FALSE)
        {
            if (builder is null)
                throw new ArgumentNullException(nameof(builder));
            return builder.Func(Sm3Handler.Verify()(hexVal)(encoding)(ignoreCase));
        }

        public static IPredicateValueRuleBuilder VerifySM3(this IValueRuleBuilder builder, Func<IHashValue, bool> checker)
        {
            return builder.VerifySM3(checker, Encoding.UTF8);
        }

        public static IPredicateValueRuleBuilder VerifySM3(this IValueRuleBuilder builder, Func<IHashValue, bool> checker, Encoding encoding)
        {
            if (builder is null)
                throw new ArgumentNullException(nameof(builder));

            if (checker is null)
                throw new ArgumentNullException(nameof(checker));

            return builder.Func(Sm3Handler.CustomVerify()(encoding)(checker));
        }
        
        public static IPredicateValueRuleBuilder<T> VerifySM3<T>(this IValueRuleBuilder<T> builder, string hexVal, IgnoreCase ignoreCase = IgnoreCase.FALSE)
        {
            return builder.VerifySM3<T>(hexVal, Encoding.UTF8, ignoreCase);
        }

        public static IPredicateValueRuleBuilder<T> VerifySM3<T>(this IValueRuleBuilder<T> builder, string hexVal, Encoding encoding, IgnoreCase ignoreCase = IgnoreCase.FALSE)
        {
            if (builder is null)
                throw new ArgumentNullException(nameof(builder));
            return builder.Func(Sm3Handler.Verify()(hexVal)(encoding)(ignoreCase));
        }

        public static IPredicateValueRuleBuilder<T> VerifySM3<T>(this IValueRuleBuilder<T> builder, Func<IHashValue, bool> checker)
        {
            return builder.VerifySM3<T>(checker, Encoding.UTF8);
        }

        public static IPredicateValueRuleBuilder<T> VerifySM3<T>(this IValueRuleBuilder<T> builder, Func<IHashValue, bool> checker, Encoding encoding)
        {
            if (builder is null)
                throw new ArgumentNullException(nameof(builder));

            if (checker is null)
                throw new ArgumentNullException(nameof(checker));

            return builder.Func(Sm3Handler.CustomVerify()(encoding)(checker));
        }
        
        public static IPredicateValueRuleBuilder<T, TVal> VerifySM3<T, TVal>(this IValueRuleBuilder<T, TVal> builder, string hexVal, IgnoreCase ignoreCase = IgnoreCase.FALSE)
        {
            return builder.VerifySM3<T, TVal>(hexVal, Encoding.UTF8, ignoreCase);
        }

        public static IPredicateValueRuleBuilder<T, TVal> VerifySM3<T, TVal>(this IValueRuleBuilder<T, TVal> builder, string hexVal, Encoding encoding, IgnoreCase ignoreCase = IgnoreCase.FALSE)
        {
            if (builder is null)
                throw new ArgumentNullException(nameof(builder));
            return builder.Func(Sm3Handler.Verify<TVal>()(hexVal)(encoding)(ignoreCase));
        }

        public static IPredicateValueRuleBuilder<T, TVal> VerifySM3<T, TVal>(this IValueRuleBuilder<T, TVal> builder, Func<IHashValue, bool> checker)
        {
            return builder.VerifySM3<T, TVal>(checker, Encoding.UTF8);
        }

        public static IPredicateValueRuleBuilder<T, TVal> VerifySM3<T, TVal>(this IValueRuleBuilder<T, TVal> builder, Func<IHashValue, bool> checker, Encoding encoding)
        {
            if (builder is null)
                throw new ArgumentNullException(nameof(builder));

            if (checker is null)
                throw new ArgumentNullException(nameof(checker));

            return builder.Func(Sm3Handler.CustomVerify<TVal>()(encoding)(checker));
        }
    }
}