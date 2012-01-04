/*
 * Copyright (c) 2010-2012 Michael Kuhn
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

#ifndef H_STORE
#define H_STORE

#include <glib.h>

struct JStore;

typedef struct JStore JStore;

#include <jcollection.h>
#include <jconnection.h>
#include <joperation.h>

JStore* j_store_new (gchar const*);
JStore* j_store_ref (JStore*);
void j_store_unref (JStore*);

gchar const* j_store_get_name (JStore*);

JConnection* j_store_get_connection (JStore*);

void j_store_create_collection (JStore*, JCollection*, JOperation*);
void j_store_get_collection (JStore*, JCollection**, gchar const*, JOperation*);
void j_store_delete_collection (JStore*, JCollection*, JOperation*);

/*
#include "collection.h"
#include "connection.h"
#include "public.h"
#include "ref_counted.h"
#include "semantics.h"

namespace JULEA
{
	class _Store : public RefCounted<_Store>
	{
		friend class RefCounted<_Store>;

		friend class Store;

		friend class Collection;
		friend class _Collection;

		private:
			_Store (string const&);

			void IsInitialized (bool) const;

			bool m_initialized;
	};

	class Store : public Public<_Store>
	{
		friend class _Connection;

		public:
			Store (string const& name)
			{
				m_p = new _Store(name);
			}

		private:
			Store (_Connection* connection, string const& name)
			{
				m_p = new _Store(connection, name);
			}
	};
}
*/

#endif
