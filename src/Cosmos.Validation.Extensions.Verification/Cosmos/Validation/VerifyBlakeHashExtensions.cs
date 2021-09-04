using System;
using System.Text;
using Cosmos.Security.Verification;
using Cosmos.Text;
using EnumsNET;

// ReSharper disable InconsistentNaming

namespace Cosmos.Validation
{
    public static class VerifyBlakeExtensions
    {
        #region Common Entry

        public static IPredicateValueRuleBuilder VerifyBlake(this IValueRuleBuilder builder, string hexVal, BlakeTypes type, IgnoreCase ignoreCase = IgnoreCase.FALSE)
        {
            return builder.VerifyBlake(hexVal, type, Encoding.UTF8, ignoreCase);
        }

        public static IPredicateValueRuleBuilder VerifyBlake(this IValueRuleBuilder builder, string hexVal, BlakeTypes type, Encoding encoding, IgnoreCase ignoreCase = IgnoreCase.FALSE)
        {
            if (builder is null)
                throw new ArgumentNullException(nameof(builder));
            return builder.Func(BlakeHandler.Verify()(hexVal)(type)(encoding)(ignoreCase)(type.GetName()));
        }

        public static IPredicateValueRuleBuilder VerifyBlake(this IValueRuleBuilder builder, Func<IHashValue, bool> checker, BlakeTypes type)
        {
            return builder.VerifyBlake(checker, type, Encoding.UTF8);
        }

        public static IPredicateValueRuleBuilder VerifyBlake(this IValueRuleBuilder builder, Func<IHashValue, bool> checker, BlakeTypes type, Encoding encoding)
        {
            if (builder is null)
                throw new ArgumentNullException(nameof(builder));

            if (checker is null)
                throw new ArgumentNullException(nameof(checker));

            return builder.Func(BlakeHandler.CustomVerify()(type)(encoding)(checker)(type.GetName()));
        }

        public static IPredicateValueRuleBuilder<T> VerifyBlake<T>(this IValueRuleBuilder<T> builder, string hexVal, BlakeTypes type, IgnoreCase ignoreCase = IgnoreCase.FALSE)
        {
            return builder.VerifyBlake<T>(hexVal, type, Encoding.UTF8, ignoreCase);
        }

        public static IPredicateValueRuleBuilder<T> VerifyBlake<T>(this IValueRuleBuilder<T> builder, string hexVal, BlakeTypes type, Encoding encoding, IgnoreCase ignoreCase = IgnoreCase.FALSE)
        {
            if (builder is null)
                throw new ArgumentNullException(nameof(builder));
            return builder.Func(BlakeHandler.Verify()(hexVal)(type)(encoding)(ignoreCase)(type.GetName()));
        }

        public static IPredicateValueRuleBuilder<T> VerifyBlake<T>(this IValueRuleBuilder<T> builder, Func<IHashValue, bool> checker, BlakeTypes type)
        {
            return builder.VerifyBlake<T>(checker, type, Encoding.UTF8);
        }

        public static IPredicateValueRuleBuilder<T> VerifyBlake<T>(this IValueRuleBuilder<T> builder, Func<IHashValue, bool> checker, BlakeTypes type, Encoding encoding)
        {
            if (builder is null)
                throw new ArgumentNullException(nameof(builder));

            if (checker is null)
                throw new ArgumentNullException(nameof(checker));

            return builder.Func(BlakeHandler.CustomVerify()(type)(encoding)(checker)(type.GetName()));
        }

        public static IPredicateValueRuleBuilder<T, TVal> VerifyBlake<T, TVal>(this IValueRuleBuilder<T, TVal> builder, string hexVal, BlakeTypes type, IgnoreCase ignoreCase = IgnoreCase.FALSE)
        {
            return builder.VerifyBlake<T, TVal>(hexVal, type, Encoding.UTF8, ignoreCase);
        }

        public static IPredicateValueRuleBuilder<T, TVal> VerifyBlake<T, TVal>(this IValueRuleBuilder<T, TVal> builder, string hexVal, BlakeTypes type, Encoding encoding, IgnoreCase ignoreCase = IgnoreCase.FALSE)
        {
            if (builder is null)
                throw new ArgumentNullException(nameof(builder));
            return builder.Func(BlakeHandler.Verify<TVal>()(hexVal)(type)(encoding)(ignoreCase)(type.GetName()));
        }

        public static IPredicateValueRuleBuilder<T, TVal> VerifyBlake<T, TVal>(this IValueRuleBuilder<T, TVal> builder, Func<IHashValue, bool> checker, BlakeTypes type)
        {
            return builder.VerifyBlake<T, TVal>(checker, type, Encoding.UTF8);
        }

        public static IPredicateValueRuleBuilder<T, TVal> VerifyBlake<T, TVal>(this IValueRuleBuilder<T, TVal> builder, Func<IHashValue, bool> checker, BlakeTypes type, Encoding encoding)
        {
            if (builder is null)
                throw new ArgumentNullException(nameof(builder));

            if (checker is null)
                throw new ArgumentNullException(nameof(checker));

            return builder.Func(BlakeHandler.CustomVerify<TVal>()(type)(encoding)(checker)(type.GetName()));
        }

        #endregion
    }
}