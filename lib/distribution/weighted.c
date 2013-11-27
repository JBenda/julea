/*
 * Copyright (c) 2010-2013 Michael Kuhn
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHORS AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED. IN NO EVENT SHALL THE AUTHORS OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 */

/**
 * \file
 **/

#include <julea-config.h>

#include <glib.h>

#include <bson.h>

#include <jconfiguration-internal.h>
#include <jtrace-internal.h>

#include "distribution.h"

/**
 * \defgroup JDistribution Distribution
 *
 * Data structures and functions for managing distributions.
 *
 * @{
 **/

/**
 * A distribution.
 **/
struct JDistributionWeighted
{
	/**
	 * The configuration.
	 **/
	JConfiguration* configuration;

	/**
	 * The length.
	 **/
	guint64 length;

	/**
	 * The offset.
	 **/
	guint64 offset;

	/**
	 * The block size.
	 */
	guint64 block_size;

	guint* weights;
	guint sum;
};

typedef struct JDistributionWeighted JDistributionWeighted;

/**
 * Distributes data to a weighted list of servers.
 *
 * \private
 *
 * \author Michael Kuhn
 *
 * \code
 * \endcode
 *
 * \param distribution A distribution.
 * \param index        A server index.
 * \param new_length   A new length.
 * \param new_offset   A new offset.
 *
 * \return TRUE on success, FALSE if the distribution is finished.
 **/
static
gboolean
distribution_distribute (gpointer data, guint* index, guint64* new_length, guint64* new_offset, guint64* block_id)
{
	JDistributionWeighted* distribution = data;

	gboolean ret = TRUE;
	guint const count = j_configuration_get_data_server_count(distribution->configuration);
	guint64 block;
	guint64 displacement;
	guint64 round;
	guint block_offset;

	j_trace_enter(G_STRFUNC);

	if (distribution->length == 0)
	{
		ret = FALSE;
		goto end;
	}

	block = distribution->offset / distribution->block_size;
	round = block / distribution->sum;
	displacement = distribution->offset % distribution->block_size;

	*index = 0;

	block_offset = block % distribution->sum;

	for (guint i = 0; i < count; i++)
	{
		if (block_offset < distribution->weights[i])
		{
			*index = i;
			break;
		}

		block_offset -= distribution->weights[i];
	}

	*new_length = MIN(distribution->length, distribution->block_size - displacement);
	*new_offset = (((round * distribution->weights[*index]) + block_offset) * distribution->block_size) + displacement;
	*block_id = block;

	distribution->length -= *new_length;
	distribution->offset += *new_length;

end:
	j_trace_leave(G_STRFUNC);

	return ret;
}

static
gpointer
distribution_new (JConfiguration* configuration)
{
	JDistributionWeighted* distribution;

	guint count;

	j_trace_enter(G_STRFUNC);

	distribution = g_slice_new(JDistributionWeighted);
	distribution->configuration = j_configuration_ref(configuration);
	distribution->length = 0;
	distribution->offset = 0;
	distribution->block_size = J_STRIPE_SIZE;

	count = j_configuration_get_data_server_count(distribution->configuration);

	distribution->sum = 0;
	distribution->weights = g_new(guint, count);

	for (guint i = 0; i < count; i++)
	{
		distribution->weights[i] = 0;
	}

	j_trace_leave(G_STRFUNC);

	return distribution;
}

/**
 * Decreases a distribution's reference count.
 * When the reference count reaches zero, frees the memory allocated for the distribution.
 *
 * \author Michael Kuhn
 *
 * \code
 * \endcode
 *
 * \param distribution A distribution.
 **/
static
void
distribution_free (gpointer data)
{
	JDistributionWeighted* distribution = data;

	g_return_if_fail(distribution != NULL);

	j_trace_enter(G_STRFUNC);

	j_configuration_unref(distribution->configuration);
	g_free(distribution->weights);

	j_trace_leave(G_STRFUNC);
}

/**
 * Sets the start index for the round robin distribution.
 *
 * \author Michael Kuhn
 *
 * \code
 * \endcode
 *
 * \param distribution A distribution.
 * \param start_index  An index.
 */
static
void
distribution_set (gpointer data, gchar const* key, guint64 value)
{
	JDistributionWeighted* distribution = data;

	g_return_if_fail(distribution != NULL);

	if (g_strcmp0(key, "block-size") == 0)
	{
		distribution->block_size = value;
	}
}

static
void
distribution_set2 (gpointer data, gchar const* key, guint64 value1, guint64 value2)
{
	JDistributionWeighted* distribution = data;

	g_return_if_fail(distribution != NULL);

	if (g_strcmp0(key, "weight") == 0)
	{
		g_return_if_fail(value1 < j_configuration_get_data_server_count(distribution->configuration));
		g_return_if_fail(value2 > 0 && value2 <= 256);

		distribution->sum += value2 - distribution->weights[value1];
		distribution->weights[value1] = value2;
	}
}

/**
 * Serializes distribution.
 *
 * \private
 *
 * \author Michael Kuhn
 *
 * \code
 * \endcode
 *
 * \param distribution Credentials.
 *
 * \return A new BSON object. Should be freed with g_slice_free().
 **/
static
void
distribution_serialize (gpointer data, bson* b)
{
	JDistributionWeighted* distribution = data;

	guint count;
	gchar numstr[16];

	g_return_if_fail(distribution != NULL);

	j_trace_enter(G_STRFUNC);

	bson_append_long(b, "BlockSize", distribution->block_size);

	count = j_configuration_get_data_server_count(distribution->configuration);

	bson_append_start_array(b, "Weights");

	for (guint i = 0; i < count; i++)
	{
		bson_numstr(numstr, i);
		bson_append_int(b, numstr, distribution->weights[i]);
	}

	bson_append_finish_array(b);

	j_trace_leave(G_STRFUNC);
}

/**
 * Deserializes distribution.
 *
 * \private
 *
 * \author Michael Kuhn
 *
 * \code
 * \endcode
 *
 * \param distribution distribution.
 * \param b           A BSON object.
 **/
static
void
distribution_deserialize (gpointer data, bson const* b)
{
	JDistributionWeighted* distribution = data;
	bson_iterator iterator;

	g_return_if_fail(distribution != NULL);
	g_return_if_fail(b != NULL);

	j_trace_enter(G_STRFUNC);

	bson_iterator_init(&iterator, b);

	while (bson_iterator_next(&iterator))
	{
		gchar const* key;

		key = bson_iterator_key(&iterator);

		if (g_strcmp0(key, "BlockSize") == 0)
		{
			distribution->block_size = bson_iterator_int(&iterator);
		}
		else if (g_strcmp0(key, "Weights") == 0)
		{
			bson_iterator siterator;

			bson_iterator_subiterator(&iterator, &siterator);

			distribution->sum = 0;

			for (guint i = 0; bson_iterator_next(&siterator); i++)
			{
				distribution->weights[i] = bson_iterator_int(&siterator);
				distribution->sum += distribution->weights[i];
			}
		}
	}

	j_trace_leave(G_STRFUNC);
}

/**
 * Initializes a distribution.
 *
 * \author Michael Kuhn
 *
 * \code
 * JDistribution* d;
 *
 * j_distribution_init(d, 0, 0);
 * \endcode
 *
 * \param length A length.
 * \param offset An offset.
 *
 * \return A new distribution. Should be freed with j_distribution_unref().
 **/
static
void
distribution_reset (gpointer data, guint64 length, guint64 offset)
{
	JDistributionWeighted* distribution = data;

	g_return_if_fail(distribution != NULL);

	j_trace_enter(G_STRFUNC);

	distribution->length = length;
	distribution->offset = offset;

	j_trace_leave(G_STRFUNC);
}

void
j_distribution_weighted_get_vtable (JDistributionVTable* vtable)
{
	vtable->distribution_new = distribution_new;
	vtable->distribution_free = distribution_free;
	vtable->distribution_set = distribution_set;
	vtable->distribution_set2 = distribution_set2;
	vtable->distribution_serialize = distribution_serialize;
	vtable->distribution_deserialize = distribution_deserialize;
	vtable->distribution_reset = distribution_reset;
	vtable->distribution_distribute = distribution_distribute;
}

/**
 * @}
 **/