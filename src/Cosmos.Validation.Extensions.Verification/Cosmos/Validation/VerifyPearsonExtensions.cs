using System;
using System.Text;
using Cosmos.Security.Verification;
using Cosmos.Text;

// ReSharper disable InconsistentNaming

namespace Cosmos.Validation
{
    public static class VerifyPearsonExtensions
    {
        public static IPredicateValueRuleBuilder VerifyPearson(this IValueRuleBuilder builder, string hexVal, IgnoreCase ignoreCase = IgnoreCase.FALSE)
        {
            return builder.VerifyPearson(hexVal, Encoding.UTF8, ignoreCase);
        }

        public static IPredicateValueRuleBuilder VerifyPearson(this IValueRuleBuilder builder, string hexVal, Encoding encoding, IgnoreCase ignoreCase = IgnoreCase.FALSE)
        {
            if (builder is null)
                throw new ArgumentNullException(nameof(builder));
            return builder.Func(PearsonHandler.Verify()(hexVal)(encoding)(ignoreCase));
        }

        public static IPredicateValueRuleBuilder VerifyPearson(this IValueRuleBuilder builder, Func<IHashValue, bool> checker)
        {
            return builder.VerifyPearson(checker, Encoding.UTF8);
        }

        public static IPredicateValueRuleBuilder VerifyPearson(this IValueRuleBuilder builder, Func<IHashValue, bool> checker, Encoding encoding)
        {
            if (builder is null)
                throw new ArgumentNullException(nameof(builder));

            if (checker is null)
                throw new ArgumentNullException(nameof(checker));

            return builder.Func(PearsonHandler.CustomVerify()(encoding)(checker));
        }

        public static IPredicateValueRuleBuilder<T> VerifyPearson<T>(this IValueRuleBuilder<T> builder, string hexVal, IgnoreCase ignoreCase = IgnoreCase.FALSE)
        {
            return builder.VerifyPearson<T>(hexVal, Encoding.UTF8, ignoreCase);
        }

        public static IPredicateValueRuleBuilder<T> VerifyPearson<T>(this IValueRuleBuilder<T> builder, string hexVal, Encoding encoding, IgnoreCase ignoreCase = IgnoreCase.FALSE)
        {
            if (builder is null)
                throw new ArgumentNullException(nameof(builder));
            return builder.Func(PearsonHandler.Verify()(hexVal)(encoding)(ignoreCase));
        }

        public static IPredicateValueRuleBuilder<T> VerifyPearson<T>(this IValueRuleBuilder<T> builder, Func<IHashValue, bool> checker)
        {
            return builder.VerifyPearson<T>(checker, Encoding.UTF8);
        }

        public static IPredicateValueRuleBuilder<T> VerifyPearson<T>(this IValueRuleBuilder<T> builder, Func<IHashValue, bool> checker, Encoding encoding)
        {
            if (builder is null)
                throw new ArgumentNullException(nameof(builder));

            if (checker is null)
                throw new ArgumentNullException(nameof(checker));

            return builder.Func(PearsonHandler.CustomVerify()(encoding)(checker));
        }

        public static IPredicateValueRuleBuilder<T, TVal> VerifyPearson<T, TVal>(this IValueRuleBuilder<T, TVal> builder, string hexVal, IgnoreCase ignoreCase = IgnoreCase.FALSE)
        {
            return builder.VerifyPearson<T, TVal>(hexVal, Encoding.UTF8, ignoreCase);
        }

        public static IPredicateValueRuleBuilder<T, TVal> VerifyPearson<T, TVal>(this IValueRuleBuilder<T, TVal> builder, string hexVal, Encoding encoding, IgnoreCase ignoreCase = IgnoreCase.FALSE)
        {
            if (builder is null)
                throw new ArgumentNullException(nameof(builder));
            return builder.Func(PearsonHandler.Verify<TVal>()(hexVal)(encoding)(ignoreCase));
        }

        public static IPredicateValueRuleBuilder<T, TVal> VerifyPearson<T, TVal>(this IValueRuleBuilder<T, TVal> builder, Func<IHashValue, bool> checker)
        {
            return builder.VerifyPearson<T, TVal>(checker, Encoding.UTF8);
        }

        public static IPredicateValueRuleBuilder<T, TVal> VerifyPearson<T, TVal>(this IValueRuleBuilder<T, TVal> builder, Func<IHashValue, bool> checker, Encoding encoding)
        {
            if (builder is null)
                throw new ArgumentNullException(nameof(builder));

            if (checker is null)
                throw new ArgumentNullException(nameof(checker));

            return builder.Func(PearsonHandler.CustomVerify<TVal>()(encoding)(checker));
        }
    }
}